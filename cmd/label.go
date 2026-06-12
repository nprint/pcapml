// SPDX-License-Identifier: Apache-2.0

//go:build pcap

package cmd

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/gopacket/gopacket/pcap"

	"github.com/schmittpaul/pcapml/internal/pcapng"
)

// labelEntry represents a parsed line from the label file.
type labelEntry struct {
	sampleID  uint64
	label     string
	bpfFilter string
	tsStart   uint64
	tsEnd     uint64
	comment   string
	bpf       *pcap.BPF
}

func runLabel(args []string) {
	fs := flag.NewFlagSet("label", flag.ExitOnError)
	var (
		inFile  string
		outFile string
		labFile string
		stats   bool
	)
	fs.StringVar(&inFile, "i", "", "input pcap file")
	fs.StringVar(&outFile, "o", "", "output pcapng file")
	fs.StringVar(&labFile, "l", "", "label file (CSV)")
	fs.BoolVar(&stats, "stats", false, "print labeling statistics")
	fs.Parse(args)

	if inFile == "" || labFile == "" || outFile == "" {
		fmt.Fprintln(os.Stderr, "usage: pcapml label -i <input.pcap> -l <labels.csv> -o <output.pcapng>")
		os.Exit(1)
	}

	// Open input pcap via libpcap
	handle, err := pcap.OpenOffline(inFile)
	if err != nil {
		log.Fatalf("failed to open %s: %v", inFile, err)
	}
	defer handle.Close()

	linkType := handle.LinkType()

	// Load and compile labels
	labels, err := loadLabelFile(labFile)
	if err != nil {
		log.Fatalf("failed to load labels: %v", err)
	}
	if len(labels) == 0 {
		log.Fatal("no labels loaded, refusing to label")
	}

	// Compile BPF filters
	for i := range labels {
		if labels[i].bpfFilter == "" {
			continue
		}
		bpf, err := handle.NewBPF(labels[i].bpfFilter)
		if err != nil {
			log.Fatalf("invalid BPF filter %q: %v", labels[i].bpfFilter, err)
		}
		labels[i].bpf = bpf
	}
	log.Printf("loaded %d labels", len(labels))

	// Open pcapng output
	writer, err := pcapng.NewWriter(outFile, uint16(linkType), 0)
	if err != nil {
		log.Fatalf("failed to create %s: %v", outFile, err)
	}
	defer writer.Close()

	var packetsReceived, packetsMatched uint64

	// Process packets
	for {
		data, ci, err := handle.ReadPacketData()
		if err != nil {
			break // EOF or error
		}
		packetsReceived++

		pktTs := uint64(ci.Timestamp.Unix())

		// Try each label (first match wins)
		for i := range labels {
			l := &labels[i]

			// Check timestamp range
			if pktTs < l.tsStart || pktTs > l.tsEnd {
				continue
			}

			// Check BPF filter
			if l.bpf != nil && !l.bpf.Matches(ci, data) {
				continue
			}

			// Match — write labeled packet
			// Encode timestamp as high=seconds, low=microseconds
			// (matching pcapml convention used by capture and sort/split/strip)
			tsHigh := uint32(ci.Timestamp.Unix())
			tsLow := uint32(ci.Timestamp.Nanosecond() / 1000)
			ts := uint64(tsHigh)<<32 | uint64(tsLow)

			if err := writer.WritePacket(ts, data, uint32(ci.Length), l.comment); err != nil {
				log.Printf("write error: %v", err)
			}
			packetsMatched++
			break
		}
	}

	if stats {
		fmt.Printf("packets received: %d\n", packetsReceived)
		fmt.Printf("packets matched:  %d\n", packetsMatched)
	}

	log.Printf("labeled %d/%d packets into %s", packetsMatched, packetsReceived, outFile)
}

func loadLabelFile(path string) ([]labelEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var labels []labelEntry
	sampleNum := uint64(0)
	hashMap := make(map[string]uint64)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ",", 3)
		if len(parts) < 2 {
			log.Printf("skipping malformed label line: %s", line)
			continue
		}

		trafficFilter := parts[0]
		metadata := parts[1]

		// Handle optional hash key for grouping
		sid := sampleNum
		if len(parts) == 3 {
			hashKey := parts[2]
			if hashKey != "" {
				if existing, ok := hashMap[hashKey]; ok {
					sid = existing
				} else {
					hashMap[hashKey] = sampleNum
				}
			}
		}

		entry := labelEntry{
			sampleID: sid,
			label:    metadata,
			tsEnd:    ^uint64(0),
			comment:  fmt.Sprintf("s=%d,proc=%s", sid, metadata),
		}

		// Parse traffic filter components
		for _, filter := range strings.Split(trafficFilter, "|") {
			kv := strings.SplitN(filter, ":", 2)
			if len(kv) != 2 {
				continue
			}
			switch kv[0] {
			case "BPF":
				entry.bpfFilter = kv[1]
			case "TS_START":
				fmt.Sscanf(kv[1], "%d", &entry.tsStart)
			case "TS_END":
				fmt.Sscanf(kv[1], "%d", &entry.tsEnd)
			}
		}

		labels = append(labels, entry)
		sampleNum++
	}

	return labels, scanner.Err()
}
