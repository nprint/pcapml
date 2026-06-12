// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strconv"

	"github.com/schmittpaul/pcapml/internal/pcapng"
)

type sortableBlock struct {
	sid uint64
	ts  uint64
	raw []byte
}

func runSort(args []string) {
	fs := flag.NewFlagSet("sort", flag.ExitOnError)
	var (
		inFile  string
		outFile string
	)
	fs.StringVar(&inFile, "i", "", "input pcapng file (labeled)")
	fs.StringVar(&outFile, "o", "", "output pcapng file")
	fs.Parse(args)

	if inFile == "" || outFile == "" {
		fmt.Fprintln(os.Stderr, "usage: pcapml sort -i <input.pcapng> -o <output.pcapng>")
		os.Exit(1)
	}

	reader, err := pcapng.NewReader(inFile)
	if err != nil {
		log.Fatalf("failed to open %s: %v", inFile, err)
	}
	defer reader.Close()

	var (
		headerBlocks [][]byte // SHB + IDB blocks to copy first
		pktBlocks    []sortableBlock
	)

	for {
		block, err := reader.ReadBlock()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("read error: %v", err)
		}

		switch block.Type {
		case pcapng.SectionHeaderType, pcapng.InterfaceDescType:
			headerBlocks = append(headerBlocks, block.RawData)

		case pcapng.EnhancedPacketType:
			sid, _ := strconv.ParseUint(block.SampleID(), 10, 64)
			pktBlocks = append(pktBlocks, sortableBlock{
				sid: sid,
				ts:  block.Timestamp(),
				raw: block.RawData,
			})
		}
	}

	// Sort by sample_id, then by timestamp
	sort.Slice(pktBlocks, func(i, j int) bool {
		if pktBlocks[i].sid != pktBlocks[j].sid {
			return pktBlocks[i].sid < pktBlocks[j].sid
		}
		return pktBlocks[i].ts < pktBlocks[j].ts
	})

	// Write output
	out, err := os.Create(outFile)
	if err != nil {
		log.Fatalf("failed to create %s: %v", outFile, err)
	}
	defer out.Close()

	for _, hb := range headerBlocks {
		if _, err := out.Write(hb); err != nil {
			log.Fatalf("write error: %v", err)
		}
	}
	for _, pb := range pktBlocks {
		if _, err := out.Write(pb.raw); err != nil {
			log.Fatalf("write error: %v", err)
		}
	}

	fmt.Printf("sorted %d packets into %s\n", len(pktBlocks), outFile)
}
