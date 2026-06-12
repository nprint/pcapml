// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"testing"

	"github.com/schmittpaul/pcapml/internal/pcapng"
)

func TestSummaryCSVOutput(t *testing.T) {
	dir := t.TempDir()

	// Create a pcapng file with known labels
	pcapngPath := filepath.Join(dir, "input.pcapng")
	w, err := pcapng.NewWriter(pcapngPath, pcapng.LinkTypeRawIPv4, 1500)
	if err != nil {
		t.Fatal(err)
	}
	pkt := []byte{0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1, 8, 8, 8, 8}

	// 3 packets labeled "firefox", 2 labeled "chrome", 1 labeled "curl"
	w.WritePacket(1000000, pkt, uint32(len(pkt)), "s=0,proc=firefox")
	w.WritePacket(2000000, pkt, uint32(len(pkt)), "s=0,proc=firefox")
	w.WritePacket(3000000, pkt, uint32(len(pkt)), "s=0,proc=firefox")
	w.WritePacket(4000000, pkt, uint32(len(pkt)), "s=1,proc=chrome")
	w.WritePacket(5000000, pkt, uint32(len(pkt)), "s=1,proc=chrome")
	w.WritePacket(6000000, pkt, uint32(len(pkt)), "s=2,proc=curl")
	w.Close()

	csvPath := filepath.Join(dir, "summary.csv")
	runSummary([]string{"-i", pcapngPath, "-csv", csvPath})

	f, err := os.Open(csvPath)
	if err != nil {
		t.Fatalf("open CSV: %v", err)
	}
	defer f.Close()

	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}

	// Header + 3 label rows
	if len(records) != 4 {
		t.Fatalf("expected 4 CSV rows, got %d", len(records))
	}
	if records[0][0] != "label" || records[0][1] != "packets" || records[0][2] != "bytes" {
		t.Errorf("unexpected header: %v", records[0])
	}

	// Rows are sorted by packet count descending: firefox(3), chrome(2), curl(1)
	labelCounts := make(map[string]string)
	for _, r := range records[1:] {
		labelCounts[r[0]] = r[1]
	}

	if labelCounts["firefox"] != "3" {
		t.Errorf("firefox packets = %q, want %q", labelCounts["firefox"], "3")
	}
	if labelCounts["chrome"] != "2" {
		t.Errorf("chrome packets = %q, want %q", labelCounts["chrome"], "2")
	}
	if labelCounts["curl"] != "1" {
		t.Errorf("curl packets = %q, want %q", labelCounts["curl"], "1")
	}
}

func TestSummaryGroupBy(t *testing.T) {
	dir := t.TempDir()

	pcapngPath := filepath.Join(dir, "input.pcapng")
	w, err := pcapng.NewWriter(pcapngPath, pcapng.LinkTypeRawIPv4, 1500)
	if err != nil {
		t.Fatal(err)
	}
	pkt := []byte{0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1, 8, 8, 8, 8}

	w.WritePacket(1000000, pkt, uint32(len(pkt)), "s=0,proc=firefox,dir=lan2wan")
	w.WritePacket(2000000, pkt, uint32(len(pkt)), "s=0,proc=chrome,dir=lan2wan")
	w.WritePacket(3000000, pkt, uint32(len(pkt)), "s=1,proc=firefox,dir=wan2lan")
	w.Close()

	csvPath := filepath.Join(dir, "summary.csv")
	runSummary([]string{"-i", pcapngPath, "-group", "dir", "-csv", csvPath})

	f, err := os.Open(csvPath)
	if err != nil {
		t.Fatalf("open CSV: %v", err)
	}
	defer f.Close()

	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}

	// Header + 2 direction rows (lan2wan=2, wan2lan=1)
	if len(records) != 3 {
		t.Fatalf("expected 3 CSV rows, got %d", len(records))
	}

	labelCounts := make(map[string]string)
	for _, r := range records[1:] {
		labelCounts[r[0]] = r[1]
	}

	if labelCounts["lan2wan"] != "2" {
		t.Errorf("lan2wan packets = %q, want %q", labelCounts["lan2wan"], "2")
	}
	if labelCounts["wan2lan"] != "1" {
		t.Errorf("wan2lan packets = %q, want %q", labelCounts["wan2lan"], "1")
	}
}

func TestSummaryTimeFilter(t *testing.T) {
	dir := t.TempDir()

	pcapngPath := filepath.Join(dir, "input.pcapng")
	w, err := pcapng.NewWriter(pcapngPath, pcapng.LinkTypeRawIPv4, 1500)
	if err != nil {
		t.Fatal(err)
	}
	pkt := []byte{0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1, 8, 8, 8, 8}

	// Timestamps: 100s, 200s, 300s (stored as microseconds)
	w.WritePacket(100_000_000, pkt, uint32(len(pkt)), "s=0,proc=early")
	w.WritePacket(200_000_000, pkt, uint32(len(pkt)), "s=1,proc=middle")
	w.WritePacket(300_000_000, pkt, uint32(len(pkt)), "s=2,proc=late")
	w.Close()

	csvPath := filepath.Join(dir, "summary.csv")
	// Filter to only include packets between 150s and 250s
	runSummary([]string{"-i", pcapngPath, "-from", "150", "-to", "250", "-csv", csvPath})

	f, err := os.Open(csvPath)
	if err != nil {
		t.Fatalf("open CSV: %v", err)
	}
	defer f.Close()

	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}

	// Header + 1 row (only "middle" at 200s)
	if len(records) != 2 {
		t.Fatalf("expected 2 CSV rows (header + 1 data), got %d", len(records))
	}
	if records[1][0] != "middle" {
		t.Errorf("filtered label = %q, want %q", records[1][0], "middle")
	}
}
