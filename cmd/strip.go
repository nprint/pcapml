// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/schmittpaul/pcapml/internal/pcap"
	"github.com/schmittpaul/pcapml/internal/pcapng"
)

func runStrip(args []string) {
	fs := flag.NewFlagSet("strip", flag.ExitOnError)
	var (
		inFile  string
		outFile string
	)
	fs.StringVar(&inFile, "i", "", "input pcapng file (labeled)")
	fs.StringVar(&outFile, "o", "", "output pcap file")
	fs.Parse(args)

	if inFile == "" || outFile == "" {
		fmt.Fprintln(os.Stderr, "usage: pcapml strip -i <input.pcapng> -o <output.pcap>")
		os.Exit(1)
	}

	reader, err := pcapng.NewReader(inFile)
	if err != nil {
		log.Fatalf("failed to open %s: %v", inFile, err)
	}
	defer reader.Close()

	var (
		writer   *pcap.Writer
		packets  uint64
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
		case pcapng.InterfaceDescType:
			if writer != nil {
				log.Fatal("pcap does not support multiple link types in a single capture")
			}
			writer, err = pcap.NewWriter(outFile, block.LinkType)
			if err != nil {
				log.Fatalf("failed to create %s: %v", outFile, err)
			}
			defer writer.Close()

		case pcapng.EnhancedPacketType:
			if writer == nil {
				log.Fatal("EPB before IDB in pcapng file")
			}
			ts := block.Timestamp()
			tsSec := uint32(ts / 1_000_000)
			tsUsec := uint32(ts % 1_000_000)
			if err := writer.WritePacket(tsSec, tsUsec, block.CapLen, block.OrigLen, block.PacketData); err != nil {
				log.Fatalf("write error: %v", err)
			}
			packets++
		}
	}

	fmt.Printf("stripped %d packets into %s\n", packets, outFile)
}
