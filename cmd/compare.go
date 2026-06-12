// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/schmittpaul/pcapml/internal/pcapng"
)

func runCompare(args []string) {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	var (
		truthFile string
		testFile  string
		csvFile   string
	)
	fs.StringVar(&truthFile, "truth", "", "ground-truth pcapng file (eBPF-labeled)")
	fs.StringVar(&testFile, "test", "", "re-labeled pcapng file (post-hoc labeled)")
	fs.StringVar(&csvFile, "csv", "", "output confusion matrix as CSV (optional)")
	fs.Parse(args)

	if truthFile == "" || testFile == "" {
		fmt.Fprintln(os.Stderr, "usage: pcapml compare -truth <ground_truth.pcapng> -test <relabeled.pcapng>")
		os.Exit(1)
	}

	truthR, err := pcapng.NewReader(truthFile)
	if err != nil {
		log.Fatalf("failed to open truth file: %v", err)
	}
	defer truthR.Close()

	testR, err := pcapng.NewReader(testFile)
	if err != nil {
		log.Fatalf("failed to open test file: %v", err)
	}
	defer testR.Close()

	// Read the first test packet
	testBlock := nextEPB(testR)

	var totalTruth, matched, correct, wrong, unlabeled int

	// confusion[truthLabel][testLabel] = count
	confusion := make(map[string]map[string]int)
	// Per-label ground-truth counts
	truthCounts := make(map[string]int)

	addConfusion := func(truth, test string) {
		if confusion[truth] == nil {
			confusion[truth] = make(map[string]int)
		}
		confusion[truth][test]++
	}

	// Two-pointer walk: truth file is the superset, test file is a subset
	// in the same packet order. For each truth packet, check if it matches
	// the current test packet (by packet data). If so, compare labels.
	for {
		truthBlock := nextEPB(truthR)
		if truthBlock == nil {
			break
		}
		totalTruth++

		truthLabel := truthBlock.Label()
		truthCounts[truthLabel]++

		if testBlock != nil && bytes.Equal(truthBlock.PacketData, testBlock.PacketData) {
			matched++
			testLabel := testBlock.Label()

			if truthLabel == testLabel {
				correct++
			} else {
				wrong++
			}
			addConfusion(truthLabel, testLabel)

			testBlock = nextEPB(testR)
		} else {
			unlabeled++
			addConfusion(truthLabel, "<unlabeled>")
		}
	}

	// Collect all labels for display
	allTruthLabels := sortedKeys(truthCounts)
	testLabelSet := make(map[string]bool)
	for _, m := range confusion {
		for k := range m {
			testLabelSet[k] = true
		}
	}
	allTestLabels := sortedKeys(testLabelSet)

	// --- Print results ---
	fmt.Println("=== pcapml Ground Truth vs Post-Hoc Comparison ===")
	fmt.Println()
	fmt.Printf("Ground truth file: %s\n", truthFile)
	fmt.Printf("Test file:         %s\n", testFile)
	fmt.Println()

	fmt.Println("--- Summary ---")
	fmt.Printf("Total packets (ground truth):  %d\n", totalTruth)
	fmt.Printf("Matched by post-hoc rules:     %d (%.1f%%)\n",
		matched, pct(matched, totalTruth))
	fmt.Printf("Unlabeled (no post-hoc match): %d (%.1f%%)\n",
		unlabeled, pct(unlabeled, totalTruth))
	fmt.Println()

	if matched > 0 {
		fmt.Println("--- Label accuracy (matched packets only) ---")
		fmt.Printf("Correct: %d (%.1f%%)\n", correct, pct(correct, matched))
		fmt.Printf("Wrong:   %d (%.1f%%)\n", wrong, pct(wrong, matched))
		fmt.Println()
	}

	// Per ground-truth label breakdown
	fmt.Println("--- Per-label breakdown ---")
	fmt.Printf("%-20s %8s %8s %8s %8s %8s\n",
		"Ground Truth", "Total", "Matched", "Correct", "Precis.", "Recall")

	for _, tl := range allTruthLabels {
		total := truthCounts[tl]
		m := confusion[tl]

		var labelMatched, labelCorrect int
		for testLabel, cnt := range m {
			if testLabel != "<unlabeled>" {
				labelMatched += cnt
			}
			if testLabel == tl {
				labelCorrect = cnt
			}
		}

		// Precision: of all packets the post-hoc method labeled as tl,
		// how many actually are tl?
		var postHocTotal int
		for _, m2 := range confusion {
			if cnt, ok := m2[tl]; ok {
				postHocTotal += cnt
			}
		}
		precision := pct(labelCorrect, postHocTotal)
		recall := pct(labelCorrect, total)

		fmt.Printf("%-20s %8d %8d %8d %7.1f%% %7.1f%%\n",
			tl, total, labelMatched, labelCorrect, precision, recall)
	}
	fmt.Println()

	// Confusion matrix
	fmt.Println("--- Confusion matrix (rows=truth, cols=post-hoc) ---")
	printConfusionMatrix(allTruthLabels, allTestLabels, confusion)

	// CSV output
	if csvFile != "" {
		writeConfusionCSV(csvFile, allTruthLabels, allTestLabels, confusion)
		fmt.Printf("\nConfusion matrix CSV written to: %s\n", csvFile)
	}
}

func nextEPB(r *pcapng.Reader) *pcapng.Block {
	for {
		b, err := r.ReadBlock()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			log.Printf("read error: %v", err)
			return nil
		}
		if b.Type == pcapng.EnhancedPacketType {
			return b
		}
	}
}

func pct(num, denom int) float64 {
	if denom == 0 {
		return 0
	}
	return float64(num) / float64(denom) * 100
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func printConfusionMatrix(truthLabels, testLabels []string, confusion map[string]map[string]int) {
	// Determine column width
	colWidth := 10
	for _, l := range testLabels {
		if len(l)+2 > colWidth {
			colWidth = len(l) + 2
		}
	}

	// Header
	fmt.Printf("%-20s", "")
	for _, tl := range testLabels {
		fmt.Printf("%*s", colWidth, tl)
	}
	fmt.Println()
	fmt.Println(strings.Repeat("-", 20+colWidth*len(testLabels)))

	// Rows
	for _, truthL := range truthLabels {
		fmt.Printf("%-20s", truthL)
		m := confusion[truthL]
		for _, testL := range testLabels {
			fmt.Printf("%*d", colWidth, m[testL])
		}
		fmt.Println()
	}
}

func writeConfusionCSV(path string, truthLabels, testLabels []string, confusion map[string]map[string]int) {
	f, err := os.Create(path)
	if err != nil {
		log.Printf("failed to create CSV: %v", err)
		return
	}
	defer f.Close()

	w := csv.NewWriter(f)

	// Header row
	header := append([]string{"ground_truth"}, testLabels...)
	w.Write(header)

	for _, truthL := range truthLabels {
		row := []string{truthL}
		m := confusion[truthL]
		for _, testL := range testLabels {
			row = append(row, fmt.Sprintf("%d", m[testL]))
		}
		w.Write(row)
	}

	w.Flush()
}
