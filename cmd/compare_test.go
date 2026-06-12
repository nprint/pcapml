// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"testing"

	"github.com/schmittpaul/pcapml/internal/pcapng"
)

func TestWriteConfusionCSV(t *testing.T) {
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "confusion.csv")

	confusion := map[string]map[string]int{
		"firefox": {"firefox": 8, "chrome": 2},
		"chrome":  {"chrome": 5, "<unlabeled>": 1},
	}
	truthLabels := []string{"chrome", "firefox"}
	testLabels := []string{"<unlabeled>", "chrome", "firefox"}

	writeConfusionCSV(csvPath, truthLabels, testLabels, confusion)

	f, err := os.Open(csvPath)
	if err != nil {
		t.Fatalf("open CSV: %v", err)
	}
	defer f.Close()

	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}

	// Header + 2 data rows
	if len(records) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(records))
	}

	// Header: ground_truth, <unlabeled>, chrome, firefox
	if records[0][0] != "ground_truth" {
		t.Errorf("header[0] = %q, want %q", records[0][0], "ground_truth")
	}

	// chrome row: chrome, 1, 5, 0
	if records[1][0] != "chrome" || records[1][1] != "1" || records[1][2] != "5" {
		t.Errorf("chrome row = %v, want [chrome 1 5 0]", records[1])
	}

	// firefox row: firefox, 0, 2, 8
	if records[2][0] != "firefox" || records[2][2] != "2" || records[2][3] != "8" {
		t.Errorf("firefox row = %v, want [firefox 0 2 8]", records[2])
	}
}

func TestCompareDetectsMislabel(t *testing.T) {
	dir := t.TempDir()

	// Truth: pkt1=appA, pkt2=appA, pkt3=appB
	truthPath := filepath.Join(dir, "truth.pcapng")
	tw, err := pcapng.NewWriter(truthPath, pcapng.LinkTypeRawIPv4, 1500)
	if err != nil {
		t.Fatal(err)
	}
	pkt1 := []byte{0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1, 8, 8, 8, 8}
	pkt2 := []byte{0x45, 0x00, 0x00, 0x28, 0x00, 0x02, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 2, 1, 1, 1, 1}
	pkt3 := []byte{0x45, 0x00, 0x00, 0x28, 0x00, 0x03, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 10, 0, 0, 3, 8, 8, 4, 4}
	tw.WritePacket(1000000, pkt1, uint32(len(pkt1)), "s=0,proc=appA")
	tw.WritePacket(2000000, pkt2, uint32(len(pkt2)), "s=0,proc=appA")
	tw.WritePacket(3000000, pkt3, uint32(len(pkt3)), "s=1,proc=appB")
	tw.Close()

	// Test: pkt1=appA (correct), pkt2=appX (WRONG), pkt3=appB (correct)
	testPath := filepath.Join(dir, "test.pcapng")
	rw, err := pcapng.NewWriter(testPath, pcapng.LinkTypeRawIPv4, 1500)
	if err != nil {
		t.Fatal(err)
	}
	rw.WritePacket(1000000, pkt1, uint32(len(pkt1)), "s=0,proc=appA")
	rw.WritePacket(2000000, pkt2, uint32(len(pkt2)), "s=0,proc=appX") // mislabeled
	rw.WritePacket(3000000, pkt3, uint32(len(pkt3)), "s=1,proc=appB")
	rw.Close()

	csvPath := filepath.Join(dir, "confusion.csv")
	runCompare([]string{"-truth", truthPath, "-test", testPath, "-csv", csvPath})

	f, err := os.Open(csvPath)
	if err != nil {
		t.Fatalf("open CSV: %v", err)
	}
	defer f.Close()

	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}

	// Header + 2 truth labels (appA, appB)
	if len(records) != 3 {
		t.Fatalf("expected 3 CSV rows, got %d", len(records))
	}

	// Build lookup: confusion[truthLabel][testLabel] = count string
	// Header row tells us column order
	header := records[0] // ground_truth, appA, appB, appX
	colIdx := make(map[string]int)
	for i, h := range header {
		colIdx[h] = i
	}

	rowIdx := make(map[string][]string)
	for _, r := range records[1:] {
		rowIdx[r[0]] = r
	}

	// appA truth row: 1 correct (appA→appA), 1 mislabeled (appA→appX)
	appARow := rowIdx["appA"]
	if appARow == nil {
		t.Fatal("missing appA row")
	}
	if appARow[colIdx["appA"]] != "1" {
		t.Errorf("appA→appA = %s, want 1", appARow[colIdx["appA"]])
	}
	if appARow[colIdx["appX"]] != "1" {
		t.Errorf("appA→appX = %s, want 1 (the mislabel)", appARow[colIdx["appX"]])
	}

	// appB truth row: 1 correct (appB→appB)
	appBRow := rowIdx["appB"]
	if appBRow == nil {
		t.Fatal("missing appB row")
	}
	if appBRow[colIdx["appB"]] != "1" {
		t.Errorf("appB→appB = %s, want 1", appBRow[colIdx["appB"]])
	}
}

func TestCompareUnlabeledPackets(t *testing.T) {
	dir := t.TempDir()

	// Truth has 3 packets, test file only has 2 (missing the middle one)
	truthPath := filepath.Join(dir, "truth.pcapng")
	tw, err := pcapng.NewWriter(truthPath, pcapng.LinkTypeRawIPv4, 1500)
	if err != nil {
		t.Fatal(err)
	}
	pkt1 := []byte{0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1, 8, 8, 8, 8}
	pkt2 := []byte{0x45, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 2, 1, 1, 1, 1}
	pkt3 := []byte{0x45, 0x00, 0x00, 0x14, 0x00, 0x03, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 3, 9, 9, 9, 9}
	tw.WritePacket(1000000, pkt1, uint32(len(pkt1)), "s=0,proc=app")
	tw.WritePacket(2000000, pkt2, uint32(len(pkt2)), "s=0,proc=app")
	tw.WritePacket(3000000, pkt3, uint32(len(pkt3)), "s=1,proc=app")
	tw.Close()

	// Test file: only pkt1 and pkt3 — pkt2 is missing (unlabeled)
	testPath := filepath.Join(dir, "test.pcapng")
	rw, err := pcapng.NewWriter(testPath, pcapng.LinkTypeRawIPv4, 1500)
	if err != nil {
		t.Fatal(err)
	}
	rw.WritePacket(1000000, pkt1, uint32(len(pkt1)), "s=0,proc=app")
	rw.WritePacket(3000000, pkt3, uint32(len(pkt3)), "s=1,proc=app")
	rw.Close()

	csvPath := filepath.Join(dir, "confusion.csv")
	runCompare([]string{"-truth", truthPath, "-test", testPath, "-csv", csvPath})

	f, err := os.Open(csvPath)
	if err != nil {
		t.Fatalf("open CSV: %v", err)
	}
	defer f.Close()

	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}

	// Find the <unlabeled> column — it should exist because one truth packet was unmatched
	header := records[0]
	unlabeledCol := -1
	for i, h := range header {
		if h == "<unlabeled>" {
			unlabeledCol = i
			break
		}
	}
	if unlabeledCol == -1 {
		t.Fatal("expected <unlabeled> column in confusion matrix for unmatched truth packet")
	}

	// The app row should have 1 unlabeled entry
	for _, r := range records[1:] {
		if r[0] == "app" {
			if r[unlabeledCol] != "1" {
				t.Errorf("app→<unlabeled> = %s, want 1", r[unlabeledCol])
			}
			return
		}
	}
	t.Error("missing app row in confusion matrix")
}
