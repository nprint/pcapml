// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"sort"

	"github.com/schmittpaul/pcapml/internal/pcapng"
)

// vantageFlow holds per-flow metadata extracted from a pcapng capture.
type vantageFlow struct {
	sampleID  string
	proc      string // proc=<name> (host only)
	dir       string // dir=<lan2wan|wan2lan|lan2lan|...>
	domain    string // dst=<domain> if present
	pktCount  int
	firstTs   uint64 // microseconds
	lastTs    uint64
	tcpSeqs   []uint32 // first N TCP sequence numbers for correlation
	udpHashes []uint64 // hash of (dst_ip, dst_port, payload prefix)
}

// dstKey is the NAT-invariant key: destination IP, destination port, protocol.
// The destination side is preserved through SNAT on the gateway.
type dstKey struct {
	dstIP   [4]byte
	dstPort uint16
	proto   uint8
}

// indexedFlow pairs a flow with its destination keys for lookup.
type indexedFlow struct {
	flow    vantageFlow
	dstKeys []dstKey
}

// matchResult pairs a host flow with its matched gateway flow.
type matchResult struct {
	hostFlow    *vantageFlow
	gwFlow      *vantageFlow
	matchMethod string
}

// domainAgreement classifies how the dst= labels compare between matched flows.
type domainAgreement int

const (
	domainAgree    domainAgreement = iota // both have dst= and they match
	domainDisagree                        // both have dst= but they differ
	domainHostOnly                        // only host has dst=
	domainGWOnly                          // only gateway has dst=
	domainNeither                         // neither has dst=
)

func (d domainAgreement) String() string {
	switch d {
	case domainAgree:
		return "agree"
	case domainDisagree:
		return "disagree"
	case domainHostOnly:
		return "host_only"
	case domainGWOnly:
		return "gw_only"
	case domainNeither:
		return "neither"
	}
	return "unknown"
}

func classifyDomainAgreement(hostDomain, gwDomain string) domainAgreement {
	hasHost := hostDomain != ""
	hasGW := gwDomain != ""
	switch {
	case hasHost && hasGW && hostDomain == gwDomain:
		return domainAgree
	case hasHost && hasGW:
		return domainDisagree
	case hasHost:
		return domainHostOnly
	case hasGW:
		return domainGWOnly
	default:
		return domainNeither
	}
}

func runVantage(args []string) {
	fs := flag.NewFlagSet("vantage", flag.ExitOnError)
	var (
		hostFile    string
		gatewayFile string
		csvFile     string
		windowSec   float64
	)
	fs.StringVar(&hostFile, "host", "", "host-mode pcapng file (process-labeled)")
	fs.StringVar(&gatewayFile, "gateway", "", "gateway-mode pcapng file (direction-labeled)")
	fs.StringVar(&csvFile, "csv", "", "output per-flow join results as CSV (optional)")
	fs.Float64Var(&windowSec, "window", 5.0, "time window in seconds for packet correlation")
	fs.Parse(args)

	if hostFile == "" || gatewayFile == "" {
		fmt.Fprintln(os.Stderr, "usage: pcapml vantage -host <host.pcapng> -gateway <gw.pcapng> [-csv out.csv] [-window 5]")
		os.Exit(1)
	}

	windowUs := uint64(windowSec * 1e6)

	log.Println("loading host capture...")
	hostFlows, hostPkts := loadVantageFlows(hostFile)
	log.Println("loading gateway capture...")
	gwFlows, gwPkts := loadVantageFlows(gatewayFile)

	log.Printf("host: %d flows, %d packets", len(hostFlows), hostPkts)
	log.Printf("gateway: %d flows, %d packets", len(gwFlows), gwPkts)

	// Index gateway flows by dstKey for NAT-aware matching
	gwByDst := make(map[dstKey][]*vantageFlow)
	for i := range gwFlows {
		for _, dk := range gwFlows[i].dstKeys {
			gwByDst[dk] = append(gwByDst[dk], &gwFlows[i].flow)
		}
	}

	// Match host flows to gateway flows
	var matches []matchResult
	gwMatched := make(map[*vantageFlow]bool)
	hostUnmatched := 0

	for i := range hostFlows {
		hf := &hostFlows[i]
		var bestGW *vantageFlow
		var bestMethod string
		bestScore := 0

		for _, dk := range hf.dstKeys {
			for _, gf := range gwByDst[dk] {
				if gwMatched[gf] {
					continue
				}
				if !vantageTimeOverlap(hf.flow.firstTs, hf.flow.lastTs, gf.firstTs, gf.lastTs, windowUs) {
					continue
				}
				score, method := correlateFlows(hf.flow, *gf)
				if score > bestScore {
					bestScore = score
					bestGW = gf
					bestMethod = method
				}
			}
		}

		if bestGW != nil {
			matches = append(matches, matchResult{
				hostFlow:    &hf.flow,
				gwFlow:      bestGW,
				matchMethod: bestMethod,
			})
			gwMatched[bestGW] = true
		} else {
			hostUnmatched++
		}
	}

	gwUnmatched := len(gwFlows) - len(gwMatched)

	// Domain agreement statistics
	agreeCounts := make(map[domainAgreement]int)
	for _, m := range matches {
		da := classifyDomainAgreement(m.hostFlow.domain, m.gwFlow.domain)
		agreeCounts[da]++
	}

	fmt.Println()
	fmt.Println("=== Cross-Vantage Comparison ===")
	fmt.Println()
	fmt.Printf("Host flows:      %d\n", len(hostFlows))
	fmt.Printf("Gateway flows:   %d\n", len(gwFlows))
	fmt.Printf("Matched flows:   %d (%.1f%% of host, %.1f%% of gateway)\n",
		len(matches),
		pct(len(matches), len(hostFlows)),
		pct(len(matches), len(gwFlows)))
	fmt.Printf("Hidden (host-only, no gateway match): %d\n", hostUnmatched)
	fmt.Printf("Dark (gateway-only, no host match):   %d\n", gwUnmatched)
	fmt.Println()

	// Domain agreement report
	if len(matches) > 0 {
		fmt.Println("--- Domain label agreement (dst=) ---")
		bothHave := agreeCounts[domainAgree] + agreeCounts[domainDisagree]
		if bothHave > 0 {
			fmt.Printf("  agree:    %d (%.1f%% of %d with both)\n",
				agreeCounts[domainAgree],
				pct(agreeCounts[domainAgree], bothHave),
				bothHave)
			fmt.Printf("  disagree: %d (%.1f%% of %d with both)\n",
				agreeCounts[domainDisagree],
				pct(agreeCounts[domainDisagree], bothHave),
				bothHave)
		}
		fmt.Printf("  host_only: %d\n", agreeCounts[domainHostOnly])
		fmt.Printf("  gw_only:   %d\n", agreeCounts[domainGWOnly])
		fmt.Printf("  neither:   %d\n", agreeCounts[domainNeither])
		fmt.Println()
	}

	// Timing offset stats
	if len(matches) > 0 {
		var deltas []float64
		for _, m := range matches {
			d := vantageAbsDiff(m.hostFlow.firstTs, m.gwFlow.firstTs)
			deltas = append(deltas, float64(d)/1e6)
		}
		sort.Float64s(deltas)
		fmt.Printf("Timing offset (first-packet delta):\n")
		fmt.Printf("  median: %.3fs\n", vantagePercentile(deltas, 50))
		fmt.Printf("  p95:    %.3fs\n", vantagePercentile(deltas, 95))
		fmt.Printf("  max:    %.3fs\n", deltas[len(deltas)-1])
		fmt.Println()
	}

	// Per-match details
	fmt.Println("--- Per-flow matches ---")
	fmt.Printf("%-8s %-20s %-10s %-25s %-25s %-10s %-12s\n",
		"HostID", "Process", "GW Dir", "Host Domain", "GW Domain", "DstAgree", "Method")
	for _, m := range matches {
		da := classifyDomainAgreement(m.hostFlow.domain, m.gwFlow.domain)
		fmt.Printf("%-8s %-20s %-10s %-25s %-25s %-10s %-12s\n",
			m.hostFlow.sampleID,
			m.hostFlow.proc,
			m.gwFlow.dir,
			vantageTruncate(m.hostFlow.domain, 25),
			vantageTruncate(m.gwFlow.domain, 25),
			da.String(),
			m.matchMethod)
	}

	if csvFile != "" {
		writeVantageCSV(csvFile, matches, hostFlows, gwFlows, gwMatched)
		log.Printf("CSV written to %s", csvFile)
	}
}

func loadVantageFlows(filename string) ([]indexedFlow, int) {
	r, err := pcapng.NewReader(filename)
	if err != nil {
		log.Fatalf("failed to open %s: %v", filename, err)
	}
	defer r.Close()

	type flowAccum struct {
		flow    vantageFlow
		dstKeys map[dstKey]bool
	}

	flows := make(map[string]*flowAccum)
	totalPkts := 0

	for {
		b, err := r.ReadBlock()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("read error in %s: %v", filename, err)
			break
		}
		if b.Type != pcapng.EnhancedPacketType {
			continue
		}
		totalPkts++

		sid := b.SampleID()
		if sid == "" {
			continue
		}

		fa, ok := flows[sid]
		if !ok {
			fa = &flowAccum{
				flow: vantageFlow{
					sampleID: sid,
					proc:     pcapng.CommentVal(b.Comment, "proc"),
					dir:      pcapng.CommentVal(b.Comment, "dir"),
					domain:   pcapng.CommentVal(b.Comment, "dst"),
					firstTs:  b.Timestamp(),
				},
				dstKeys: make(map[dstKey]bool),
			}
			flows[sid] = fa
		}

		fa.flow.pktCount++
		ts := b.Timestamp()
		if ts < fa.flow.firstTs {
			fa.flow.firstTs = ts
		}
		if ts > fa.flow.lastTs {
			fa.flow.lastTs = ts
		}

		// Parse IP header for destination key and correlation data
		pkt := b.PacketData
		if len(pkt) < 20 {
			continue
		}
		ihl := int(pkt[0]&0x0F) * 4
		if ihl < 20 || len(pkt) < ihl+4 {
			continue
		}

		proto := pkt[9]
		var dstIP [4]byte
		copy(dstIP[:], pkt[16:20])
		dstPort := uint16(pkt[ihl+2])<<8 | uint16(pkt[ihl+3])

		fa.dstKeys[dstKey{dstIP: dstIP, dstPort: dstPort, proto: proto}] = true

		// TCP: extract sequence number for correlation
		if proto == 6 && len(pkt) >= ihl+8 {
			seq := binary.BigEndian.Uint32(pkt[ihl+4 : ihl+8])
			if len(fa.flow.tcpSeqs) < 32 {
				fa.flow.tcpSeqs = append(fa.flow.tcpSeqs, seq)
			}
		}

		// UDP: hash (dst_ip, dst_port, payload prefix) for correlation
		if proto == 17 && len(pkt) > ihl+8 {
			payloadStart := ihl + 8
			h := sha256.New()
			h.Write(dstIP[:])
			h.Write([]byte{byte(dstPort >> 8), byte(dstPort)})
			end := payloadStart + 32
			if end > len(pkt) {
				end = len(pkt)
			}
			h.Write(pkt[payloadStart:end])
			sum := h.Sum(nil)
			hashVal := binary.BigEndian.Uint64(sum[:8])
			if len(fa.flow.udpHashes) < 32 {
				fa.flow.udpHashes = append(fa.flow.udpHashes, hashVal)
			}
		}
	}

	result := make([]indexedFlow, 0, len(flows))
	for _, fa := range flows {
		keys := make([]dstKey, 0, len(fa.dstKeys))
		for dk := range fa.dstKeys {
			keys = append(keys, dk)
		}
		result = append(result, indexedFlow{flow: fa.flow, dstKeys: keys})
	}
	return result, totalPkts
}

// correlateFlows scores how well two flows match using TCP seq numbers or UDP payload hashes.
func correlateFlows(host, gw vantageFlow) (int, string) {
	// TCP sequence number matching
	if len(host.tcpSeqs) > 0 && len(gw.tcpSeqs) > 0 {
		gwSet := make(map[uint32]bool, len(gw.tcpSeqs))
		for _, s := range gw.tcpSeqs {
			gwSet[s] = true
		}
		overlap := 0
		for _, s := range host.tcpSeqs {
			if gwSet[s] {
				overlap++
			}
		}
		if overlap > 0 {
			return overlap * 10, "tcp_seq"
		}
	}

	// UDP payload hash matching
	if len(host.udpHashes) > 0 && len(gw.udpHashes) > 0 {
		gwSet := make(map[uint64]bool, len(gw.udpHashes))
		for _, h := range gw.udpHashes {
			gwSet[h] = true
		}
		overlap := 0
		for _, h := range host.udpHashes {
			if gwSet[h] {
				overlap++
			}
		}
		if overlap > 0 {
			return overlap * 5, "udp_hash"
		}
	}

	// Fallback: time proximity + packet count similarity
	timeDelta := vantageAbsDiff(host.firstTs, gw.firstTs)
	countRatio := float64(min(host.pktCount, gw.pktCount)) / float64(max(host.pktCount, gw.pktCount))
	if timeDelta < 2e6 && countRatio > 0.5 {
		return 1, "time+count"
	}

	return 0, ""
}

func vantageTimeOverlap(aStart, aEnd, bStart, bEnd, window uint64) bool {
	return !(aStart > bEnd+window || bStart > aEnd+window)
}

func vantageAbsDiff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

func vantagePercentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := p / 100 * float64(len(sorted)-1)
	lower := int(math.Floor(idx))
	upper := int(math.Ceil(idx))
	if lower == upper || upper >= len(sorted) {
		return sorted[lower]
	}
	frac := idx - float64(lower)
	return sorted[lower]*(1-frac) + sorted[upper]*frac
}

func vantageTruncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-2] + ".."
}

func writeVantageCSV(filename string, matches []matchResult, hostFlows, gwFlows []indexedFlow, gwMatched map[*vantageFlow]bool) {
	f, err := os.Create(filename)
	if err != nil {
		log.Printf("failed to create CSV %s: %v", filename, err)
		return
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	w.Write([]string{"type", "host_sample_id", "host_process", "host_dir", "host_domain",
		"gw_sample_id", "gw_dir", "gw_domain",
		"domain_agreement", "host_pkts", "gw_pkts", "match_method"})

	for _, m := range matches {
		da := classifyDomainAgreement(m.hostFlow.domain, m.gwFlow.domain)
		w.Write([]string{
			"matched",
			m.hostFlow.sampleID,
			m.hostFlow.proc,
			m.hostFlow.dir,
			m.hostFlow.domain,
			m.gwFlow.sampleID,
			m.gwFlow.dir,
			m.gwFlow.domain,
			da.String(),
			fmt.Sprintf("%d", m.hostFlow.pktCount),
			fmt.Sprintf("%d", m.gwFlow.pktCount),
			m.matchMethod,
		})
	}

	// Hidden host flows (no gateway match)
	matchedHostIDs := make(map[string]bool)
	for _, m := range matches {
		matchedHostIDs[m.hostFlow.sampleID] = true
	}
	for i := range hostFlows {
		if !matchedHostIDs[hostFlows[i].flow.sampleID] {
			w.Write([]string{
				"hidden",
				hostFlows[i].flow.sampleID,
				hostFlows[i].flow.proc,
				hostFlows[i].flow.dir,
				hostFlows[i].flow.domain,
				"", "", "",
				"",
				fmt.Sprintf("%d", hostFlows[i].flow.pktCount),
				"", "",
			})
		}
	}

	// Dark gateway flows (no host match)
	for i := range gwFlows {
		if !gwMatched[&gwFlows[i].flow] {
			w.Write([]string{
				"dark",
				"", "", "", "",
				gwFlows[i].flow.sampleID,
				gwFlows[i].flow.dir,
				gwFlows[i].flow.domain,
				"",
				"",
				fmt.Sprintf("%d", gwFlows[i].flow.pktCount),
				"",
			})
		}
	}
}
