// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/binary"
	"testing"
)

func TestResolverDNSResponse(t *testing.T) {
	res := newResolver()

	// Build a minimal DNS response for "example.com" -> 93.184.216.34
	// over UDP from port 53
	pkt := buildDNSResponsePacket(t, "example.com", [4]byte{93, 184, 216, 34}, 300)

	isDNS := res.processDNS(pkt)
	if !isDNS {
		t.Fatal("expected packet to be identified as DNS")
	}

	ip := [4]byte{93, 184, 216, 34}
	domain := res.lookup(ip)
	if domain != "example.com" {
		t.Errorf("expected domain 'example.com', got %q", domain)
	}
}

func TestResolverSNI(t *testing.T) {
	res := newResolver()

	// Manually add a mapping to test resolution
	res.addMapping([4]byte{1, 2, 3, 4}, "test.example.com", 300)

	// Build a minimal IPv4 packet to 1.2.3.4
	pkt := make([]byte, 40) // IPv4 header + TCP header stub
	pkt[0] = 0x45           // version 4, IHL 5
	pkt[9] = 6              // TCP
	copy(pkt[12:16], []byte{10, 0, 0, 1}) // src
	copy(pkt[16:20], []byte{1, 2, 3, 4})  // dst

	domain := res.resolveLabel(pkt)
	if domain != "test.example.com" {
		t.Errorf("expected 'test.example.com', got %q", domain)
	}
}

func TestResolverEnrichLabelSrcIP(t *testing.T) {
	res := newResolver()
	res.addMapping([4]byte{5, 6, 7, 8}, "server.example.com", 300)

	// Packet FROM 5.6.7.8 (ingress — server is source)
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	pkt[9] = 6
	copy(pkt[12:16], []byte{5, 6, 7, 8})  // src = server
	copy(pkt[16:20], []byte{10, 0, 0, 1}) // dst = us

	domain := res.resolveLabel(pkt)
	if domain != "server.example.com" {
		t.Errorf("expected 'server.example.com', got %q", domain)
	}
}

func TestResolverNonDNSPacket(t *testing.T) {
	res := newResolver()

	// Build a TCP packet to port 443 (not DNS)
	pkt := make([]byte, 40)
	pkt[0] = 0x45 // IPv4, IHL=5
	pkt[9] = 6    // TCP
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{1, 2, 3, 4})
	pkt[20] = 0x00 // src port high
	pkt[21] = 0x50 // src port 80
	pkt[22] = 0x01 // dst port high
	pkt[23] = 0xBB // dst port 443

	isDNS := res.processDNS(pkt)
	if isDNS {
		t.Error("expected non-DNS packet")
	}
}

func TestExtractSNI(t *testing.T) {
	// Build a minimal TLS ClientHello with SNI "www.example.com"
	sni := buildTLSClientHelloPacket(t, "www.example.com")
	result := extractSNI(sni)
	if result != "www.example.com" {
		t.Errorf("expected 'www.example.com', got %q", result)
	}
}

func TestExtractSNINoTLS(t *testing.T) {
	// Plain TCP packet, no TLS
	pkt := make([]byte, 60)
	pkt[0] = 0x45
	pkt[9] = 6 // TCP
	pkt[32] = 0x50 // data offset = 5 (20 bytes)
	// payload is just zeros, not TLS
	result := extractSNI(pkt)
	if result != "" {
		t.Errorf("expected empty SNI, got %q", result)
	}
}

func TestDNSNameCompression(t *testing.T) {
	// Test DNS name reading with compression pointer
	dns := []byte{
		// Name at offset 0: "\x07example\x03com\x00"
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		// Compressed name at offset 13: pointer to offset 0
		0xC0, 0x00,
	}

	name, off := readDNSName(dns, 0)
	if name != "example.com" {
		t.Errorf("expected 'example.com', got %q", name)
	}
	if off != 13 {
		t.Errorf("expected offset 13, got %d", off)
	}

	name2, off2 := readDNSName(dns, 13)
	if name2 != "example.com" {
		t.Errorf("expected 'example.com' via compression, got %q", name2)
	}
	if off2 != 15 {
		t.Errorf("expected offset 15, got %d", off2)
	}
}

// buildDNSResponsePacket creates a raw IPv4/UDP packet containing a DNS A record response.
func buildDNSResponsePacket(t *testing.T, domain string, ip [4]byte, ttl uint32) []byte {
	t.Helper()

	// Build DNS payload
	dns := buildDNSAResponse(domain, ip, ttl)

	// UDP header (8 bytes)
	udpLen := 8 + len(dns)
	udp := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udp[0:2], 53)             // src port (DNS server)
	binary.BigEndian.PutUint16(udp[2:4], 12345)          // dst port
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen)) // length
	copy(udp[8:], dns)

	// IPv4 header (20 bytes)
	totalLen := 20 + udpLen
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(totalLen))
	ipHdr[9] = 17 // UDP
	copy(ipHdr[12:16], []byte{8, 8, 8, 8})    // src: DNS server
	copy(ipHdr[16:20], []byte{10, 0, 0, 1})   // dst: us

	pkt := append(ipHdr, udp...)
	return pkt
}

// buildDNSAResponse creates a DNS response payload with one A record.
func buildDNSAResponse(domain string, ip [4]byte, ttl uint32) []byte {
	var dns []byte

	// Header: ID(2) + flags(2) + QD(2) + AN(2) + NS(2) + AR(2) = 12
	dns = append(dns, 0x00, 0x01)       // ID
	dns = append(dns, 0x81, 0x80)       // flags: response, recursion available
	dns = append(dns, 0x00, 0x01)       // QDCOUNT = 1
	dns = append(dns, 0x00, 0x01)       // ANCOUNT = 1
	dns = append(dns, 0x00, 0x00)       // NSCOUNT = 0
	dns = append(dns, 0x00, 0x00)       // ARCOUNT = 0

	// Question section: encode domain name
	nameBytes := encodeDNSName(domain)
	dns = append(dns, nameBytes...)
	dns = append(dns, 0x00, 0x01) // QTYPE = A
	dns = append(dns, 0x00, 0x01) // QCLASS = IN

	// Answer section: pointer to name in question + A record
	dns = append(dns, 0xC0, 0x0C) // name pointer to offset 12
	dns = append(dns, 0x00, 0x01) // TYPE = A
	dns = append(dns, 0x00, 0x01) // CLASS = IN
	ttlBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ttlBytes, ttl)
	dns = append(dns, ttlBytes...) // TTL
	dns = append(dns, 0x00, 0x04)  // RDLENGTH = 4
	dns = append(dns, ip[:]...)    // RDATA = IP

	return dns
}

// encodeDNSName encodes a domain name into DNS wire format.
func encodeDNSName(name string) []byte {
	var buf []byte
	for _, label := range splitDomain(name) {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00)
	return buf
}

func splitDomain(name string) []string {
	var labels []string
	current := ""
	for _, c := range name {
		if c == '.' {
			if current != "" {
				labels = append(labels, current)
			}
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		labels = append(labels, current)
	}
	return labels
}

// buildTLSClientHelloPacket creates a raw IPv4/TCP packet with a TLS ClientHello containing the given SNI.
func buildTLSClientHelloPacket(t *testing.T, serverName string) []byte {
	t.Helper()

	// Build SNI extension
	sniExt := buildSNIExtension(serverName)

	// Extensions: length(2) + sniExt
	var extensions []byte
	extLen := make([]byte, 2)
	binary.BigEndian.PutUint16(extLen, uint16(len(sniExt)))
	extensions = append(extensions, extLen...)
	extensions = append(extensions, sniExt...)

	// ClientHello body: version(2) + random(32) + sessionID(1) + cipherSuites(4) + compression(2) + extensions
	var clientHello []byte
	clientHello = append(clientHello, 0x03, 0x03)        // TLS 1.2
	clientHello = append(clientHello, make([]byte, 32)...) // random
	clientHello = append(clientHello, 0x00)               // session ID length = 0
	clientHello = append(clientHello, 0x00, 0x02, 0x00, 0x2F) // 1 cipher suite
	clientHello = append(clientHello, 0x01, 0x00)         // 1 compression method (null)
	clientHello = append(clientHello, extensions...)

	// Handshake: type(1) + length(3)
	var handshake []byte
	handshake = append(handshake, 0x01) // ClientHello
	hsLen := len(clientHello)
	handshake = append(handshake, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	handshake = append(handshake, clientHello...)

	// TLS record: type(1) + version(2) + length(2)
	var record []byte
	record = append(record, 0x16)       // Handshake
	record = append(record, 0x03, 0x01) // TLS 1.0 record version
	recLen := make([]byte, 2)
	binary.BigEndian.PutUint16(recLen, uint16(len(handshake)))
	record = append(record, recLen...)
	record = append(record, handshake...)

	// TCP header (20 bytes, data offset = 5)
	tcpHdr := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHdr[0:2], 54321) // src port
	binary.BigEndian.PutUint16(tcpHdr[2:4], 443)   // dst port
	tcpHdr[12] = 0x50 // data offset = 5 (20 bytes)

	// IPv4 header (20 bytes)
	totalLen := 20 + 20 + len(record)
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(totalLen))
	ipHdr[9] = 6 // TCP
	copy(ipHdr[12:16], []byte{10, 0, 0, 1})
	copy(ipHdr[16:20], []byte{93, 184, 216, 34})

	pkt := append(ipHdr, tcpHdr...)
	pkt = append(pkt, record...)
	return pkt
}

func buildSNIExtension(serverName string) []byte {
	// server_name extension (type 0x0000)
	nameBytes := []byte(serverName)

	// SNI entry: type(1) + length(2) + name
	var sniEntry []byte
	sniEntry = append(sniEntry, 0x00) // host_name
	nameLen := make([]byte, 2)
	binary.BigEndian.PutUint16(nameLen, uint16(len(nameBytes)))
	sniEntry = append(sniEntry, nameLen...)
	sniEntry = append(sniEntry, nameBytes...)

	// SNI list: length(2) + entries
	var sniList []byte
	listLen := make([]byte, 2)
	binary.BigEndian.PutUint16(listLen, uint16(len(sniEntry)))
	sniList = append(sniList, listLen...)
	sniList = append(sniList, sniEntry...)

	// Extension: type(2) + length(2) + data
	var ext []byte
	ext = append(ext, 0x00, 0x00) // server_name type
	extDataLen := make([]byte, 2)
	binary.BigEndian.PutUint16(extDataLen, uint16(len(sniList)))
	ext = append(ext, extDataLen...)
	ext = append(ext, sniList...)

	return ext
}
