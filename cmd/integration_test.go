// SPDX-License-Identifier: Apache-2.0

//go:build pcap

package cmd

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/schmittpaul/pcapml/internal/pcap"
	"github.com/schmittpaul/pcapml/internal/pcapng"
)

func TestSortSubcommand(t *testing.T) {
	inFile := "../test/sort-test/test.pcapng"
	outFile := filepath.Join(t.TempDir(), "sorted.pcapng")

	runSort([]string{"-i", inFile, "-o", outFile})

	// Verify output is valid and sorted
	r, err := pcapng.NewReader(outFile)
	if err != nil {
		t.Fatalf("open output: %v", err)
	}
	defer r.Close()

	var (
		count      int
		lastSID    uint64
		lastTS     uint64
		firstBlock bool = true
	)

	for {
		b, err := r.ReadBlock()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if b.Type != pcapng.EnhancedPacketType {
			continue
		}

		count++
		sidStr := b.SampleID()
		sid, _ := strconv.ParseUint(sidStr, 10, 64)
		ts := b.Timestamp()

		if !firstBlock {
			// Verify sort order: SID ascending, then TS ascending within SID
			if sid == lastSID && ts < lastTS {
				t.Errorf("packet %d: timestamp went backwards within sid %d (%d < %d)",
					count, sid, ts, lastTS)
			}
			if sid < lastSID {
				t.Errorf("packet %d: SID went backwards (%d < %d)", count, sid, lastSID)
			}
		}

		if sid != lastSID {
			lastTS = 0
		}
		lastSID = sid
		lastTS = ts
		firstBlock = false
	}

	if count != 151 {
		t.Errorf("expected 151 packets, got %d", count)
	}
}

func TestSplitSubcommand(t *testing.T) {
	inFile := "../test/sample-test/test.pcapng"
	outDir := filepath.Join(t.TempDir(), "split")

	runSplit([]string{"-i", inFile, "-o", outDir})

	// Check metadata.csv exists
	metaPath := filepath.Join(outDir, "metadata.csv")
	if _, err := os.Stat(metaPath); err != nil {
		t.Fatalf("metadata.csv missing: %v", err)
	}

	// Count pcap files
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}

	pcapCount := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".pcap" {
			pcapCount++
		}
	}

	if pcapCount != 10 {
		t.Errorf("expected 10 pcap files, got %d", pcapCount)
	}
}

func TestStripSubcommand(t *testing.T) {
	inFile := "../test/sample-test/test.pcapng"
	outFile := filepath.Join(t.TempDir(), "stripped.pcap")

	runStrip([]string{"-i", inFile, "-o", outFile})

	// Verify output is valid pcap
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	// Check pcap magic number
	if len(data) < 4 {
		t.Fatal("output too small")
	}
	magic := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	if magic != 0xA1B2C3D4 {
		t.Errorf("pcap magic = %#x, want %#x", magic, 0xA1B2C3D4)
	}

	// File should be substantial (151 packets)
	if len(data) < 1000 {
		t.Errorf("output too small: %d bytes", len(data))
	}
}

func TestLabelSubcommand(t *testing.T) {
	inFile := "../test/label-test/test.pcap"
	labFile := "../test/label-test/labels.txt"
	outFile := filepath.Join(t.TempDir(), "labeled.pcapng")

	runLabel([]string{"-i", inFile, "-l", labFile, "-o", outFile})

	// Read back and verify
	r, err := pcapng.NewReader(outFile)
	if err != nil {
		t.Fatalf("open output: %v", err)
	}
	defer r.Close()

	var (
		count    int
		comments int
	)

	for {
		b, err := r.ReadBlock()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if b.Type != pcapng.EnhancedPacketType {
			continue
		}
		count++
		if b.Comment != "" {
			comments++
		}
	}

	if count != 151 {
		t.Errorf("expected 151 packets, got %d", count)
	}
	if comments != 151 {
		t.Errorf("expected 151 comments, got %d", comments)
	}
}

func TestLabelSortSplitRoundTrip(t *testing.T) {
	dir := t.TempDir()
	labeledFile := filepath.Join(dir, "labeled.pcapng")
	sortedFile := filepath.Join(dir, "sorted.pcapng")
	splitDir := filepath.Join(dir, "split")

	// Label
	runLabel([]string{
		"-i", "../test/label-test/test.pcap",
		"-l", "../test/label-test/labels.txt",
		"-o", labeledFile,
	})

	// Sort
	runSort([]string{"-i", labeledFile, "-o", sortedFile})

	// Split
	runSplit([]string{"-i", sortedFile, "-o", splitDir})

	// Verify split produced pcap files
	entries, err := os.ReadDir(splitDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}

	pcapCount := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".pcap" {
			pcapCount++
		}
	}

	// 9 samples (ubuntu-14.4 and web-server share sample ID via hashme)
	if pcapCount != 9 {
		t.Errorf("expected 9 pcap files, got %d", pcapCount)
	}

	// Count total packets across all pcap files
	totalPkts := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".pcap" {
			continue
		}
		fpath := filepath.Join(splitDir, e.Name())
		totalPkts += countPcapPackets(t, fpath)
	}

	if totalPkts != 151 {
		t.Errorf("expected 151 total packets across splits, got %d", totalPkts)
	}

	_ = pcap.NewWriter // ensure import
}

func countPcapPackets(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	// Skip 24-byte global header, then count 16-byte packet headers
	offset := 24
	count := 0
	for offset < len(data) {
		if offset+16 > len(data) {
			break
		}
		capLen := uint32(data[offset+8]) | uint32(data[offset+9])<<8 |
			uint32(data[offset+10])<<16 | uint32(data[offset+11])<<24
		offset += 16 + int(capLen)
		count++
	}
	return count
}
