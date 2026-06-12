// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
)

const version = "0.1.0"

func Execute() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "capture":
		runCapture(os.Args[2:])
	case "split":
		runSplit(os.Args[2:])
	case "sort":
		runSort(os.Args[2:])
	case "strip":
		runStrip(os.Args[2:])
	case "label":
		runLabel(os.Args[2:])
	case "compare":
		runCompare(os.Args[2:])
	case "vantage":
		runVantage(os.Args[2:])
	case "summary":
		runSummary(os.Args[2:])
	case "version":
		fmt.Printf("pcapml %s\n", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `pcapml — ground-truth labeled network traffic datasets

Usage:
  pcapml <subcommand> [flags]

Subcommands:
  capture   %s
              --mode host    (default) process attribution via cgroup eBPF
              --mode gateway network-path capture via TC eBPF on WAN interface
  label     Apply labels to a pcap file using a label file
  split     Split a labeled pcapng into per-sample pcap files
  sort      Sort a labeled pcapng by sample_id then timestamp
  strip     Remove labels from pcapng, producing a plain pcap
  compare   Compare ground-truth labels against post-hoc labels
  vantage   Cross-vantage flow join: compare host vs gateway captures
  summary   Per-label packet count summary for a pcapng file
  version   Print version

Run 'pcapml <subcommand> -h' for subcommand help.
`, captureDescription)
}
