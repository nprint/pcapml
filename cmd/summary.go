// SPDX-License-Identifier: Apache-2.0

package cmd

import (
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

func runSummary(args []string) {
	fs := flag.NewFlagSet("summary", flag.ExitOnError)
	var (
		inFile  string
		csvFile string
		from    uint64
		to      uint64
		groupBy string
	)
	fs.StringVar(&inFile, "i", "", "input pcapng file")
	fs.StringVar(&csvFile, "csv", "", "write CSV output to file")
	fs.Uint64Var(&from, "from", 0, "start Unix timestamp (seconds, inclusive)")
	fs.Uint64Var(&to, "to", ^uint64(0), "end Unix timestamp (seconds, inclusive)")
	fs.StringVar(&groupBy, "group", "", "group by a specific comment field (e.g., dst, proc, dir); default uses Label() heuristic")
	fs.Parse(args)

	if inFile == "" {
		fmt.Fprintln(os.Stderr, "usage: pcapml summary -i <input.pcapng> [-from <ts>] [-to <ts>] [-group <field>] [-csv <out.csv>]")
		os.Exit(1)
	}

	reader, err := pcapng.NewReader(inFile)
	if err != nil {
		log.Fatalf("failed to open %s: %v", inFile, err)
	}
	defer reader.Close()

	type stats struct {
		packets uint64
		bytes   uint64
	}
	counts := make(map[string]*stats)
	var total uint64

	for {
		block, err := reader.ReadBlock()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("read error: %v", err)
		}
		if block.Type != pcapng.EnhancedPacketType {
			continue
		}

		tsSec := block.Timestamp() / 1_000_000
		if tsSec < from || tsSec > to {
			continue
		}

		var label string
		if groupBy != "" {
			label = pcapng.CommentVal(block.Comment, groupBy)
		} else {
			label = block.Label()
		}
		if label == "" {
			label = "<unlabeled>"
		}
		if counts[label] == nil {
			counts[label] = &stats{}
		}
		counts[label].packets++
		counts[label].bytes += uint64(block.OrigLen)
		total++
	}

	type entry struct {
		name string
		*stats
	}
	entries := make([]entry, 0, len(counts))
	for name, s := range counts {
		entries = append(entries, entry{name, s})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].packets > entries[j].packets
	})

	header := "Label"
	if groupBy != "" {
		header = strings.ToUpper(groupBy[:1]) + groupBy[1:]
	}
	fmt.Printf("%-40s %10s %8s\n", header, "Packets", "Pct")
	fmt.Printf("%-40s %10s %8s\n", "-----", "-------", "---")
	for _, e := range entries {
		pct := float64(e.packets) / float64(total) * 100
		fmt.Printf("%-40s %10d %7.1f%%\n", e.name, e.packets, pct)
	}
	fmt.Printf("\nTotal: %d packets\n", total)

	if csvFile != "" {
		f, err := os.Create(csvFile)
		if err != nil {
			log.Fatalf("failed to create %s: %v", csvFile, err)
		}
		defer f.Close()
		w := csv.NewWriter(f)
		_ = w.Write([]string{"label", "packets", "bytes"})
		for _, e := range entries {
			_ = w.Write([]string{e.name, fmt.Sprint(e.packets), fmt.Sprint(e.bytes)})
		}
		w.Flush()
	}
}
