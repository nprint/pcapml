// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// quicV1InitialSalt is the fixed salt for QUIC v1 Initial packet key derivation (RFC 9001 §5.2).
var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

// extractQUICSNI attempts to extract the SNI from a QUIC v1 Initial packet.
// pkt is a raw IPv4 packet (no link-layer header).
// Only client-to-server packets (dst port 443) are considered.
func extractQUICSNI(pkt []byte) string {
	if len(pkt) < 28 { // IP header (20) + UDP header (8)
		return ""
	}
	if pkt[9] != 17 { // not UDP
		return ""
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return ""
	}
	// Only client→server direction (dst port 443)
	dstPort := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	if dstPort != 443 {
		return ""
	}
	return parseQUICInitialSNI(pkt[ihl+8:])
}

// parseQUICInitialSNI decrypts a QUIC v1 Initial packet and extracts the SNI.
func parseQUICInitialSNI(data []byte) string {
	if len(data) < 23 {
		return ""
	}
	// Must be a long header (bit 7 set) with the fixed bit (bit 6 set)
	if data[0]&0xc0 != 0xc0 {
		return ""
	}
	// Long packet type bits 4-5: 0x00 = Initial
	if (data[0]>>4)&0x03 != 0x00 {
		return ""
	}
	// QUIC v1 only
	if binary.BigEndian.Uint32(data[1:5]) != 0x00000001 {
		return ""
	}

	off := 5

	// Destination Connection ID
	if off >= len(data) {
		return ""
	}
	dcidLen := int(data[off])
	off++
	if off+dcidLen > len(data) {
		return ""
	}
	dcid := data[off : off+dcidLen]
	off += dcidLen

	// Source Connection ID
	if off >= len(data) {
		return ""
	}
	scidLen := int(data[off])
	off++
	off += scidLen
	if off > len(data) {
		return ""
	}

	// Token
	tokenLen, n := quicVarInt(data, off)
	if n <= 0 {
		return ""
	}
	off += n + int(tokenLen)
	if off > len(data) {
		return ""
	}

	// Payload length
	payloadLen, n := quicVarInt(data, off)
	if n <= 0 {
		return ""
	}
	off += n

	// off is now at the header-protected packet number
	pnOffset := off

	// Need pnOffset + 4 + 16 bytes to form the AES-ECB sample for header protection removal
	if pnOffset+20 > len(data) {
		return ""
	}

	// Derive Initial keys from DCID
	key, iv, hp := deriveQUICv1InitialKeys(dcid)

	// Remove header protection:
	// sample = encrypted_payload[4:20] relative to the packet number start
	mask := aesECBEncrypt(hp, data[pnOffset+4:pnOffset+20])

	unmaskedFirst := data[0] ^ (mask[0] & 0x0f) // long header: low 4 bits
	pnLen := int(unmaskedFirst&0x03) + 1

	if pnOffset+pnLen > len(data) {
		return ""
	}

	// Unmasked packet number
	pnBytes := make([]byte, pnLen)
	for i := range pnLen {
		pnBytes[i] = data[pnOffset+i] ^ mask[1+i]
	}

	// AAD = full header with unmasked first byte and packet number
	headerLen := pnOffset + pnLen
	aad := make([]byte, headerLen)
	copy(aad, data[:headerLen])
	aad[0] = unmaskedFirst
	for i := range pnLen {
		aad[pnOffset+i] = pnBytes[i]
	}

	// Ciphertext: from end of packet number to end of payload (or data, if truncated)
	cipherStart := pnOffset + pnLen
	cipherEnd := pnOffset + int(payloadLen)
	if cipherEnd > len(data) {
		cipherEnd = len(data)
	}
	if cipherStart >= cipherEnd {
		return ""
	}
	ciphertext := data[cipherStart:cipherEnd]

	// Nonce = IV XOR left-padded packet number
	var pn uint64
	for _, b := range pnBytes {
		pn = pn<<8 | uint64(b)
	}
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	for i := range 8 {
		nonce[len(nonce)-8+i] ^= byte(pn >> (56 - 8*i))
	}

	// Decrypt
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return ""
	}

	return parseQUICCryptoSNI(plaintext)
}

// deriveQUICv1InitialKeys derives the AEAD key, IV, and header-protection key
// for a QUIC v1 Initial packet from the Destination Connection ID (RFC 9001 §5).
func deriveQUICv1InitialKeys(dcid []byte) (key, iv, hp []byte) {
	initialSecret := hkdfExtract(quicV1InitialSalt, dcid)
	clientSecret := hkdfExpandLabel(initialSecret, "client in", nil, 32)
	key = hkdfExpandLabel(clientSecret, "quic key", nil, 16)
	iv = hkdfExpandLabel(clientSecret, "quic iv", nil, 12)
	hp = hkdfExpandLabel(clientSecret, "quic hp", nil, 16)
	return
}

// hkdfExtract computes HKDF-Extract(salt, ikm) using SHA-256 (RFC 5869).
func hkdfExtract(salt, ikm []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// hkdfExpandLabel implements TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1).
// length must be ≤ 32 (one HMAC-SHA256 round suffices for all QUIC uses).
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	fullLabel := "tls13 " + label
	info := make([]byte, 0, 2+1+len(fullLabel)+1+len(context))
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, byte(len(context)))
	info = append(info, context...)

	mac := hmac.New(sha256.New, secret)
	mac.Write(info)
	mac.Write([]byte{0x01})
	return mac.Sum(nil)[:length]
}

// aesECBEncrypt encrypts a single 16-byte block using AES with no chaining (ECB),
// used for QUIC header protection mask generation.
func aesECBEncrypt(key, block []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		return make([]byte, 16)
	}
	out := make([]byte, 16)
	c.Encrypt(out, block)
	return out
}

// quicVarInt reads a QUIC variable-length integer (RFC 9000 §16).
// Returns the value and bytes consumed, or (0, -1) on error.
func quicVarInt(data []byte, off int) (uint64, int) {
	if off >= len(data) {
		return 0, -1
	}
	switch data[off] >> 6 {
	case 0:
		return uint64(data[off] & 0x3f), 1
	case 1:
		if off+2 > len(data) {
			return 0, -1
		}
		return uint64(binary.BigEndian.Uint16(data[off:off+2])) & 0x3fff, 2
	case 2:
		if off+4 > len(data) {
			return 0, -1
		}
		return uint64(binary.BigEndian.Uint32(data[off:off+4])) & 0x3fffffff, 4
	case 3:
		if off+8 > len(data) {
			return 0, -1
		}
		return binary.BigEndian.Uint64(data[off:off+8]) & 0x3fffffffffffffff, 8
	}
	return 0, -1
}

// parseQUICCryptoSNI walks decrypted QUIC frame data looking for a CRYPTO frame
// at offset 0, then extracts the SNI from the TLS ClientHello inside it.
func parseQUICCryptoSNI(data []byte) string {
	off := 0
	for off < len(data) {
		frameType, n := quicVarInt(data, off)
		if n <= 0 {
			break
		}
		off += n

		switch frameType {
		case 0x00: // PADDING — single zero byte, just continue
		case 0x01: // PING — no payload
		case 0x06: // CRYPTO
			cryptoOffset, n := quicVarInt(data, off)
			if n <= 0 {
				return ""
			}
			off += n
			cryptoLen, n := quicVarInt(data, off)
			if n <= 0 {
				return ""
			}
			off += n
			end := off + int(cryptoLen)
			if end > len(data) {
				end = len(data) // tolerate snap-len truncation
			}
			if cryptoOffset == 0 && end > off {
				return parseTLSHandshakeSNI(data[off:end])
			}
			off = end
		default:
			return "" // not a frame type we expect before CRYPTO
		}
	}
	return ""
}

// parseTLSHandshakeSNI extracts the SNI from a raw TLS handshake message.
// Unlike parseTLSClientHelloSNI, this does not expect a TLS record header —
// QUIC delivers handshake messages directly in CRYPTO frames without the record layer.
func parseTLSHandshakeSNI(data []byte) string {
	// Prepend a synthetic TLS record header so we can reuse parseTLSClientHelloSNI.
	// Record type 0x16 (Handshake) + version 0x0303 + length.
	if len(data) == 0 {
		return ""
	}
	wrapped := make([]byte, 5+len(data))
	wrapped[0] = 0x16
	wrapped[1] = 0x03
	wrapped[2] = 0x03
	binary.BigEndian.PutUint16(wrapped[3:5], uint16(len(data)))
	copy(wrapped[5:], data)
	return parseTLSClientHelloSNI(wrapped)
}
