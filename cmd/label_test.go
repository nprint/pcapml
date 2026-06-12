// SPDX-License-Identifier: Apache-2.0

//go:build pcap

package cmd

import (
	"os"
	"testing"
)

func TestLoadLabelFile(t *testing.T) {
	path := "../test/label-test/labels.txt"
	labels, err := loadLabelFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if len(labels) != 10 {
		t.Fatalf("expected 10 labels, got %d", len(labels))
	}

	// Check first label
	if labels[0].bpfFilter != "host 192.168.10.25" {
		t.Errorf("label 0 BPF = %q, want %q", labels[0].bpfFilter, "host 192.168.10.25")
	}
	if labels[0].label != "mac os" {
		t.Errorf("label 0 metadata = %q, want %q", labels[0].label, "mac os")
	}
	if labels[0].sampleID != 0 {
		t.Errorf("label 0 sampleID = %d, want 0", labels[0].sampleID)
	}

	// Check hash key grouping: ubuntu-14.4 (index 1) and web-server (index 5)
	// both have hash key "hashme", so they should share the same sample ID
	if labels[1].sampleID != labels[5].sampleID {
		t.Errorf("hash key grouping failed: label 1 sid=%d, label 5 sid=%d (should match)",
			labels[1].sampleID, labels[5].sampleID)
	}

	// Labels without hash key should have unique sample IDs
	if labels[0].sampleID == labels[2].sampleID {
		t.Error("labels 0 and 2 should have different sample IDs")
	}
}

func TestLoadLabelFileComments(t *testing.T) {
	f, err := os.CreateTemp("", "pcapml-labels-*.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	f.WriteString("# This is a comment\n")
	f.WriteString("BPF:host 10.0.0.1,server\n")
	f.WriteString("\n") // empty line
	f.WriteString("BPF:tcp port 80,http\n")
	f.Close()

	labels, err := loadLabelFile(f.Name())
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if len(labels) != 2 {
		t.Fatalf("expected 2 labels, got %d", len(labels))
	}
	if labels[0].bpfFilter != "host 10.0.0.1" {
		t.Errorf("label 0 BPF = %q", labels[0].bpfFilter)
	}
	if labels[1].bpfFilter != "tcp port 80" {
		t.Errorf("label 1 BPF = %q", labels[1].bpfFilter)
	}
}

func TestLoadLabelFileTimestamps(t *testing.T) {
	f, err := os.CreateTemp("", "pcapml-labels-*.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	f.WriteString("BPF:host 10.0.0.1|TS_START:1700000000|TS_END:1700003600,bounded\n")
	f.Close()

	labels, err := loadLabelFile(f.Name())
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if len(labels) != 1 {
		t.Fatalf("expected 1 label, got %d", len(labels))
	}
	if labels[0].tsStart != 1700000000 {
		t.Errorf("ts_start = %d, want 1700000000", labels[0].tsStart)
	}
	if labels[0].tsEnd != 1700003600 {
		t.Errorf("ts_end = %d, want 1700003600", labels[0].tsEnd)
	}
}

func TestLoadLabelFileNotFound(t *testing.T) {
	_, err := loadLabelFile("/nonexistent/labels.csv")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}
