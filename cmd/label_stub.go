// SPDX-License-Identifier: Apache-2.0

//go:build !pcap

package cmd

import (
	"fmt"
	"os"
)

func runLabel(_ []string) {
	fmt.Fprintln(os.Stderr, "label subcommand not available: build with '-tags pcap' to enable (requires libpcap)")
	os.Exit(1)
}
