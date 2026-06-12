// SPDX-License-Identifier: Apache-2.0

package pcap

import (
	"encoding/binary"
	"os"
	"testing"
)

func TestWriterGlobalHeader(t *testing.T) {
	f, err := os.CreateTemp("", "pcapml-test-*.pcap")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	f.Close()
	defer os.Remove(name)

	w, err := NewWriter(name, 1) // LINKTYPE_ETHERNET
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	w.Close()

	// Verify global header
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}

	if len(data) != 24 { // pcap global header is 24 bytes
		t.Fatalf("file size = %d, want 24", len(data))
	}

	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != pcapMagic {
		t.Errorf("magic = %#x, want %#x", magic, pcapMagic)
	}

	versionMajor := binary.LittleEndian.Uint16(data[4:6])
	if versionMajor != pcapVersionMaj {
		t.Errorf("version major = %d, want %d", versionMajor, pcapVersionMaj)
	}

	linkType := binary.LittleEndian.Uint32(data[20:24])
	if linkType != 1 {
		t.Errorf("link type = %d, want 1", linkType)
	}
}

func TestWriterPacket(t *testing.T) {
	f, err := os.CreateTemp("", "pcapml-test-*.pcap")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	f.Close()
	defer os.Remove(name)

	w, err := NewWriter(name, 1)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	pktData := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}
	err = w.WritePacket(1000, 500000, 6, 6, pktData)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	w.Close()

	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}

	// 24 byte global header + 16 byte packet header + 6 bytes data = 46
	if len(data) != 46 {
		t.Fatalf("file size = %d, want 46", len(data))
	}

	// Check packet header (starts at offset 24)
	tsSec := binary.LittleEndian.Uint32(data[24:28])
	tsUsec := binary.LittleEndian.Uint32(data[28:32])
	capLen := binary.LittleEndian.Uint32(data[32:36])
	origLen := binary.LittleEndian.Uint32(data[36:40])

	if tsSec != 1000 {
		t.Errorf("ts_sec = %d, want 1000", tsSec)
	}
	if tsUsec != 500000 {
		t.Errorf("ts_usec = %d, want 500000", tsUsec)
	}
	if capLen != 6 {
		t.Errorf("cap_len = %d, want 6", capLen)
	}
	if origLen != 6 {
		t.Errorf("orig_len = %d, want 6", origLen)
	}

	// Check packet data
	for i, b := range pktData {
		if data[40+i] != b {
			t.Errorf("byte %d = %#x, want %#x", i, data[40+i], b)
		}
	}
}

func TestWriterDoubleClose(t *testing.T) {
	f, err := os.CreateTemp("", "pcapml-test-*.pcap")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	f.Close()
	defer os.Remove(name)

	w, err := NewWriter(name, 1)
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
