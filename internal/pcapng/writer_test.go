// SPDX-License-Identifier: Apache-2.0

package pcapng

import (
	"io"
	"os"
	"testing"
)

func TestWriterRoundTrip(t *testing.T) {
	f, err := os.CreateTemp("", "pcapml-test-*.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	f.Close()
	defer os.Remove(name)

	// Write
	w, err := NewWriter(name, LinkTypeEthernet, 65535)
	if err != nil {
		t.Fatalf("create writer: %v", err)
	}

	packets := []struct {
		ts      uint64
		data    []byte
		origLen uint32
		comment string
	}{
		{1000000, []byte{0xDE, 0xAD, 0xBE, 0xEF}, 4, "s=0,proc=test-label"},
		{2000000, []byte{0x01, 0x02, 0x03}, 3, "s=0,proc=test-label"},
		{3000000, []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00}, 5, "s=1,proc=other-label"},
	}

	for _, p := range packets {
		if err := w.WritePacket(p.ts, p.data, p.origLen, p.comment); err != nil {
			t.Fatalf("write packet: %v", err)
		}
	}
	w.Close()

	// Read back
	r, err := NewReader(name)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer r.Close()

	var epbCount int
	var linkType uint16

	for {
		b, err := r.ReadBlock()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read block: %v", err)
		}

		switch b.Type {
		case InterfaceDescType:
			linkType = b.LinkType
		case EnhancedPacketType:
			if epbCount >= len(packets) {
				t.Fatal("more EPBs than expected")
			}
			expected := packets[epbCount]

			if b.Comment != expected.comment {
				t.Errorf("packet %d: comment = %q, want %q", epbCount, b.Comment, expected.comment)
			}
			if b.Timestamp() != expected.ts {
				t.Errorf("packet %d: ts = %d, want %d", epbCount, b.Timestamp(), expected.ts)
			}
			if int(b.CapLen) != len(expected.data) {
				t.Errorf("packet %d: cap_len = %d, want %d", epbCount, b.CapLen, len(expected.data))
			}
			if b.OrigLen != expected.origLen {
				t.Errorf("packet %d: orig_len = %d, want %d", epbCount, b.OrigLen, expected.origLen)
			}
			for i := range expected.data {
				if i < len(b.PacketData) && b.PacketData[i] != expected.data[i] {
					t.Errorf("packet %d: byte %d = %x, want %x", epbCount, i, b.PacketData[i], expected.data[i])
				}
			}

			epbCount++
		}
	}

	if linkType != LinkTypeEthernet {
		t.Errorf("link type = %d, want %d", linkType, LinkTypeEthernet)
	}
	if epbCount != len(packets) {
		t.Errorf("EPB count = %d, want %d", epbCount, len(packets))
	}
}

func TestWriterSampleIDAndLabel(t *testing.T) {
	f, err := os.CreateTemp("", "pcapml-test-*.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	f.Close()
	defer os.Remove(name)

	w, err := NewWriter(name, LinkTypeRawIPv4, 1500)
	if err != nil {
		t.Fatalf("create writer: %v", err)
	}
	w.WritePacket(100, []byte{0x45, 0x00}, 2, "s=42,proc=firefox,dir=e")
	w.Close()

	r, err := NewReader(name)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer r.Close()

	for {
		b, err := r.ReadBlock()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if b.Type == EnhancedPacketType {
			if sid := b.SampleID(); sid != "42" {
				t.Errorf("sample ID = %q, want %q", sid, "42")
			}
			if label := b.Label(); label != "firefox" {
				t.Errorf("label = %q, want %q", label, "firefox")
			}
			return
		}
	}
	t.Error("no EPB found")
}

func TestWriterGatewayLabel(t *testing.T) {
	f, err := os.CreateTemp("", "pcapml-test-*.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	f.Close()
	defer os.Remove(name)

	w, err := NewWriter(name, LinkTypeRawIPv4, 1500)
	if err != nil {
		t.Fatalf("create writer: %v", err)
	}
	// Gateway mode label: no proc, dst used as Label() fallback
	w.WritePacket(100, []byte{0x45, 0x00}, 2, "s=7,dir=wan2lan,dst=youtube.com")
	w.Close()

	r, err := NewReader(name)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer r.Close()

	for {
		b, err := r.ReadBlock()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if b.Type == EnhancedPacketType {
			if sid := b.SampleID(); sid != "7" {
				t.Errorf("sample ID = %q, want %q", sid, "7")
			}
			if label := b.Label(); label != "youtube.com" {
				t.Errorf("label = %q, want %q", label, "youtube.com")
			}
			return
		}
	}
	t.Error("no EPB found")
}

func TestPad4(t *testing.T) {
	cases := []struct {
		n    uint32
		want uint32
	}{
		{0, 0},
		{1, 3},
		{2, 2},
		{3, 1},
		{4, 0},
		{5, 3},
		{100, 0},
		{101, 3},
	}
	for _, tc := range cases {
		got := pad4(tc.n)
		if got != tc.want {
			t.Errorf("pad4(%d) = %d, want %d", tc.n, got, tc.want)
		}
	}
}

func TestWriterDoubleClose(t *testing.T) {
	f, err := os.CreateTemp("", "pcapml-test-*.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	f.Close()
	defer os.Remove(name)

	w, err := NewWriter(name, LinkTypeEthernet, 65535)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("first close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second close: %v", err)
	}
}
