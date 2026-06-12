// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/hex"
	"testing"
)

// TestQUICv1KeyDerivation verifies the QUIC v1 Initial key derivation against
// the test vectors from RFC 9001 Appendix A.
func TestQUICv1KeyDerivation(t *testing.T) {
	// RFC 9001 Appendix A: DCID = 0x8394c8f03e515708
	dcid, _ := hex.DecodeString("8394c8f03e515708")

	key, iv, hp := deriveQUICv1InitialKeys(dcid)

	// Expected values from RFC 9001 Appendix A.1
	wantKey := "1f369613dd76d5467730efcbe3b1a22d"
	wantIV := "fa044b2f42a3fd3b46fb255c"
	wantHP := "9f50449e04a0e810283a1e9933adedd2"

	if got := hex.EncodeToString(key); got != wantKey {
		t.Errorf("key mismatch\n got  %s\n want %s", got, wantKey)
	}
	if got := hex.EncodeToString(iv); got != wantIV {
		t.Errorf("iv mismatch\n got  %s\n want %s", got, wantIV)
	}
	if got := hex.EncodeToString(hp); got != wantHP {
		t.Errorf("hp mismatch\n got  %s\n want %s", got, wantHP)
	}
}

// TestQUICVarInt exercises the variable-length integer decoder.
func TestQUICVarInt(t *testing.T) {
	cases := []struct {
		data []byte
		want uint64
		n    int
	}{
		{[]byte{0x00}, 0, 1},
		{[]byte{0x3f}, 63, 1},
		{[]byte{0x40, 0x01}, 1, 2},
		{[]byte{0x7f, 0xff}, 16383, 2},
		{[]byte{0x80, 0x00, 0x00, 0x01}, 1, 4},
		{[]byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, 1, 8},
	}
	for _, tc := range cases {
		v, n := quicVarInt(tc.data, 0)
		if v != tc.want || n != tc.n {
			t.Errorf("quicVarInt(%x) = (%d, %d), want (%d, %d)", tc.data, v, n, tc.want, tc.n)
		}
	}
}

// TestHKDFExpandLabel verifies HKDF-Expand-Label against RFC 9001 Appendix A vectors.
func TestHKDFExpandLabel(t *testing.T) {
	// From RFC 9001 Appendix A.1:
	// initial_secret derived from DCID 0x8394c8f03e515708
	dcid, _ := hex.DecodeString("8394c8f03e515708")
	initialSecret := hkdfExtract(quicV1InitialSalt, dcid)

	wantInitial := "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"
	if got := hex.EncodeToString(initialSecret); got != wantInitial {
		t.Errorf("initial_secret mismatch\n got  %s\n want %s", got, wantInitial)
	}

	clientSecret := hkdfExpandLabel(initialSecret, "client in", nil, 32)
	wantClient := "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
	if got := hex.EncodeToString(clientSecret); got != wantClient {
		t.Errorf("client_initial_secret mismatch\n got  %s\n want %s", got, wantClient)
	}
}
