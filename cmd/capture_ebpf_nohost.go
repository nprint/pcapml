// SPDX-License-Identifier: Apache-2.0

//go:build ebpf && !(386 || amd64)

package cmd

import (
	"flag"
	"log"
)

const captureDescription = "Live capture with eBPF (gateway mode only on this architecture)"

func runCapture(args []string) {
	fs := flag.NewFlagSet("capture", flag.ExitOnError)
	var (
		outFile    string
		mode       string
		wanIface   string
		snapLen    uint
		includeDNS bool
		noResolve  bool
	)

	fs.StringVar(&outFile, "o", "capture.pcapng", "output pcapng file")
	fs.StringVar(&mode, "mode", "gateway", "capture mode: gateway (network path via TC eBPF on WAN interface)")
	fs.StringVar(&wanIface, "wan", "", "WAN interface (direction is inferred from this interface)")
	fs.UintVar(&snapLen, "snap-len", 1500, "max bytes to capture per packet")
	fs.BoolVar(&includeDNS, "include-dns", false, "include DNS (port 53) traffic in capture")
	fs.BoolVar(&noResolve, "no-resolve", false, "disable DNS/SNI domain resolution in labels")

	fs.Parse(args)

	if mode != "gateway" {
		log.Fatal("only gateway mode is available on this architecture (host mode requires x86)")
	}

	runCaptureGateway(outFile, snapLen, wanIface, includeDNS, noResolve)
}
