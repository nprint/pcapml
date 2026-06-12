// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/schmittpaul/pcapml/internal/pcap"
	"github.com/schmittpaul/pcapml/internal/pcapng"
)

func runSplit(args []string) {
	fs := flag.NewFlagSet("split", flag.ExitOnError)
	var (
		inFile string
		outDir string
	)
	fs.StringVar(&inFile, "i", "", "input pcapng file (labeled)")
	fs.StringVar(&outDir, "o", "", "output directory")
	fs.Parse(args)

	if inFile == "" || outDir == "" {
		fmt.Fprintln(os.Stderr, "usage: pcapml split -i <input.pcapng> -o <outdir>")
		os.Exit(1)
	}

	if err := os.MkdirAll(outDir, 0777); err != nil {
		log.Fatalf("failed to create output directory: %v", err)
	}

	reader, err := pcapng.NewReader(inFile)
	if err != nil {
		log.Fatalf("failed to open %s: %v", inFile, err)
	}
	defer reader.Close()

	metaPath := filepath.Join(outDir, "metadata.csv")
	metaFile, err := os.Create(metaPath)
	if err != nil {
		log.Fatalf("failed to create metadata file: %v", err)
	}
	defer metaFile.Close()
	fmt.Fprintln(metaFile, "File,Label")

	var (
		curSID      string
		curWriter   *pcap.Writer
		curLinkType uint16
		samples     uint64
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
			curLinkType = block.LinkType

		case pcapng.EnhancedPacketType:
			if block.Comment == "" {
				continue
			}

			sid := block.SampleID()
			label := block.Label()

			if sid != curSID {
				if curWriter != nil {
					curWriter.Close()
				}

				curSID = sid
				samples++
				outName := filepath.Base(sid) + "_" + filepath.Base(label) + ".pcap"
				fmt.Fprintf(metaFile, "%s,%s\n", outName, label)

				outPath := filepath.Join(outDir, outName)
				curWriter, err = pcap.NewWriter(outPath, curLinkType)
				if err != nil {
					log.Fatalf("failed to create %s: %v", outPath, err)
				}
			}

			ts := block.Timestamp()
			tsSec := uint32(ts / 1_000_000)
			tsUsec := uint32(ts % 1_000_000)
			if err := curWriter.WritePacket(tsSec, tsUsec, block.CapLen, block.OrigLen, block.PacketData); err != nil {
				log.Fatalf("write error: %v", err)
			}
		}
	}

	if curWriter != nil {
		curWriter.Close()
	}

	fmt.Printf("split %d samples into %s\n", samples, outDir)
}
