// SPDX-License-Identifier: Apache-2.0

//go:build !ebpf

package cmd

import (
	"fmt"
	"os"
)

const captureDescription = "Live capture (not available — build with '-tags ebpf' on Linux)"

func runCapture(_ []string) {
	fmt.Fprintln(os.Stderr, "capture subcommand not available: build with '-tags ebpf' on Linux to enable eBPF live capture")
	os.Exit(1)
}
