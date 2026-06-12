// SPDX-License-Identifier: Apache-2.0

//go:build ebpf

package cmd

import (
	"net"
	"testing"
)

func TestParseFlowKey(t *testing.T) {
	// Build a minimal IPv4/TCP packet: 10.0.0.1:1234 -> 10.0.0.2:80
	pkt := make([]byte, 24) // 20-byte IP header + 4 bytes for ports
	pkt[0] = 0x45           // version 4, IHL 5
	pkt[9] = 6              // TCP
	copy(pkt[12:16], net.IP{10, 0, 0, 1}.To4())
	copy(pkt[16:20], net.IP{10, 0, 0, 2}.To4())
	pkt[20] = 0x04 // src port high byte
	pkt[21] = 0xD2 // src port low byte (1234)
	pkt[22] = 0x00 // dst port high byte
	pkt[23] = 0x50 // dst port low byte (80)

	fk, ok := parseFlowKey(pkt)
	if !ok {
		t.Fatal("parseFlowKey returned false")
	}
	if fk.proto != 6 {
		t.Errorf("proto = %d, want 6", fk.proto)
	}

	// Normalized: smaller IP first. 10.0.0.1 < 10.0.0.2
	if fk.ipA != [4]byte{10, 0, 0, 1} {
		t.Errorf("ipA = %v, want 10.0.0.1", fk.ipA)
	}
	if fk.ipB != [4]byte{10, 0, 0, 2} {
		t.Errorf("ipB = %v, want 10.0.0.2", fk.ipB)
	}
	if fk.portA != 1234 {
		t.Errorf("portA = %d, want 1234", fk.portA)
	}
	if fk.portB != 80 {
		t.Errorf("portB = %d, want 80", fk.portB)
	}
}

func TestParseFlowKeyNormalization(t *testing.T) {
	// Forward: 10.0.0.1:1234 -> 10.0.0.2:80
	fwd := make([]byte, 24)
	fwd[0] = 0x45
	fwd[9] = 6
	copy(fwd[12:16], net.IP{10, 0, 0, 1}.To4())
	copy(fwd[16:20], net.IP{10, 0, 0, 2}.To4())
	fwd[20] = 0x04
	fwd[21] = 0xD2
	fwd[22] = 0x00
	fwd[23] = 0x50

	// Reverse: 10.0.0.2:80 -> 10.0.0.1:1234
	rev := make([]byte, 24)
	rev[0] = 0x45
	rev[9] = 6
	copy(rev[12:16], net.IP{10, 0, 0, 2}.To4())
	copy(rev[16:20], net.IP{10, 0, 0, 1}.To4())
	rev[20] = 0x00
	rev[21] = 0x50
	rev[22] = 0x04
	rev[23] = 0xD2

	fkFwd, ok1 := parseFlowKey(fwd)
	fkRev, ok2 := parseFlowKey(rev)
	if !ok1 || !ok2 {
		t.Fatal("parseFlowKey returned false")
	}
	if fkFwd != fkRev {
		t.Errorf("forward and reverse flow keys differ:\n  fwd=%+v\n  rev=%+v", fkFwd, fkRev)
	}
}

func TestParseFlowKeyTooShort(t *testing.T) {
	_, ok := parseFlowKey([]byte{0x45, 0x00})
	if ok {
		t.Error("expected false for packet too short")
	}
	_, ok = parseFlowKey(nil)
	if ok {
		t.Error("expected false for nil packet")
	}
}

func TestClassifyDirection(t *testing.T) {
	_, lanNet, _ := net.ParseCIDR("192.168.1.0/24")
	cidrs := []*net.IPNet{lanNet}

	cases := []struct {
		src  net.IP
		dst  net.IP
		want string
	}{
		{net.IP{192, 168, 1, 10}, net.IP{8, 8, 8, 8}, "lan2wan"},
		{net.IP{8, 8, 8, 8}, net.IP{192, 168, 1, 10}, "wan2lan"},
		{net.IP{192, 168, 1, 10}, net.IP{192, 168, 1, 20}, "lan2lan"},
		{net.IP{8, 8, 8, 8}, net.IP{1, 1, 1, 1}, "wan2wan"},
	}

	for _, tc := range cases {
		pkt := make([]byte, 20)
		pkt[0] = 0x45
		copy(pkt[12:16], tc.src.To4())
		copy(pkt[16:20], tc.dst.To4())
		got := classifyDirection(pkt, cidrs)
		if got != tc.want {
			t.Errorf("classifyDirection(%s->%s) = %q, want %q", tc.src, tc.dst, got, tc.want)
		}
	}
}
