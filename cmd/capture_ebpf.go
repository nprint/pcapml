// SPDX-License-Identifier: Apache-2.0

//go:build ebpf && (386 || amd64)

package cmd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/schmittpaul/pcapml/internal/pcapng"
)

const captureDescription = "Live capture with eBPF (exact process attribution, Linux only)"

const (
	cfgSnapLen    = 0
	cfgUseAllow   = 1
	cfgUseDeny    = 2
	cfgIncludeDNS = 3
	cfgCgroupInfo = 4
)

func runCapture(args []string) {
	fs := flag.NewFlagSet("capture", flag.ExitOnError)
	var (
		outFile    string
		mode       string
		wanIface   string
		allow      string
		deny       string
		lanNets    string
		snapLen    uint
		cgroupP    string
		includeDNS bool
		noResolve  bool
		cgroupInfo bool
	)

	fs.StringVar(&outFile, "o", "capture.pcapng", "output pcapng file")
	fs.StringVar(&mode, "mode", "host", "capture mode: host (process attribution) or gateway (network path)")
	fs.StringVar(&wanIface, "wan", "", "WAN interface for gateway mode (direction is inferred from this interface)")
	fs.StringVar(&allow, "allow", "", "comma-separated allow list of process names (host mode only)")
	fs.StringVar(&deny, "deny", "", "comma-separated deny list of process names (host mode only)")
	fs.StringVar(&lanNets, "lan", "", "comma-separated LAN CIDRs for direction classification (e.g., 192.168.1.0/24); auto-detected from interfaces if omitted")
	fs.UintVar(&snapLen, "snap-len", maxPktLen, "max bytes to capture per packet")
	fs.StringVar(&cgroupP, "cgroup", "/sys/fs/cgroup", "cgroup v2 path to attach to (host mode only)")
	fs.BoolVar(&includeDNS, "include-dns", false, "include DNS (port 53) traffic in capture")
	fs.BoolVar(&noResolve, "no-resolve", false, "disable DNS/SNI domain resolution in labels")
	fs.BoolVar(&cgroupInfo, "cgroup-info", false, "include cgroup path in packet labels (host mode only)")

	fs.Parse(args)

	if mode == "gateway" {
		runCaptureGateway(outFile, snapLen, wanIface, includeDNS, noResolve)
		return
	}

	if mode != "host" {
		log.Fatalf("unknown capture mode %q (use 'host' or 'gateway')", mode)
	}

	if allow != "" && deny != "" {
		log.Fatal("cannot use both --allow and --deny")
	}

	// Parse or auto-detect LAN CIDRs for direction classification
	var lanCIDRs []*net.IPNet
	if lanNets != "" {
		for _, cidr := range strings.Split(lanNets, ",") {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Fatalf("invalid LAN CIDR %q: %v", cidr, err)
			}
			lanCIDRs = append(lanCIDRs, network)
		}
		log.Printf("LAN networks (from -lan flag): %v", lanCIDRs)
	} else {
		lanCIDRs = detectLANCIDRs()
		if len(lanCIDRs) > 0 {
			log.Printf("LAN networks (auto-detected from interfaces): %v", lanCIDRs)
		} else {
			log.Println("no LAN networks detected; direction labels will use lan2wan/wan2lan (from BPF egress/ingress)")
		}
	}

	// Compute boot time offset for wall-clock timestamps
	bootOffset, err := getBootTimeOffset()
	if err != nil {
		log.Fatalf("failed to get boot time offset: %v", err)
	}

	// Load eBPF objects
	objs := pcapmlObjects{}
	if err := loadPcapmlObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("verifier error:\n%+v", ve)
		}
		log.Fatalf("failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Populate config map
	if err := objs.PcapmlConfig.Update(uint32(cfgSnapLen), uint32(snapLen), ebpf.UpdateAny); err != nil {
		log.Fatalf("failed to set snap_len config: %v", err)
	}
	resolve := !noResolve

	// When resolution is enabled, we need DNS packets from eBPF for parsing,
	// even if the user doesn't want them in the output file.
	if includeDNS || resolve {
		if err := objs.PcapmlConfig.Update(uint32(cfgIncludeDNS), uint32(1), ebpf.UpdateAny); err != nil {
			log.Fatalf("failed to set include_dns config: %v", err)
		}
		if includeDNS {
			log.Println("DNS traffic (port 53) will be included in capture")
		}
	}

	// Enable cgroup info collection in eBPF
	if cgroupInfo {
		if err := objs.PcapmlConfig.Update(uint32(cfgCgroupInfo), uint32(1), ebpf.UpdateAny); err != nil {
			log.Fatalf("failed to set cgroup_info config: %v", err)
		}
		log.Println("cgroup info recording enabled")
	}

	// Initialize resolver for DNS/SNI domain resolution
	var res *resolver
	if resolve {
		res = newResolver()
		log.Println("domain resolution enabled: labels will include dst=<domain> from DNS/SNI")
	}

	// Populate allow/deny lists
	if allow != "" {
		if err := objs.PcapmlConfig.Update(uint32(cfgUseAllow), uint32(1), ebpf.UpdateAny); err != nil {
			log.Fatalf("failed to set allow config: %v", err)
		}
		for _, name := range strings.Split(allow, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			var key [maxCommLen]byte
			copy(key[:], name)
			if err := objs.CommAllow.Update(key, uint8(1), ebpf.UpdateAny); err != nil {
				log.Fatalf("failed to add %q to allow list: %v", name, err)
			}
			log.Printf("allow: %s", name)
		}
	}
	if deny != "" {
		if err := objs.PcapmlConfig.Update(uint32(cfgUseDeny), uint32(1), ebpf.UpdateAny); err != nil {
			log.Fatalf("failed to set deny config: %v", err)
		}
		for _, name := range strings.Split(deny, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			var key [maxCommLen]byte
			copy(key[:], name)
			if err := objs.CommDeny.Update(key, uint8(1), ebpf.UpdateAny); err != nil {
				log.Fatalf("failed to add %q to deny list: %v", name, err)
			}
			log.Printf("deny: %s", name)
		}
	}

	// Attach kprobes
	kpTcpConnect, err := link.Kprobe("tcp_connect", objs.KpTcpConnect, nil)
	if err != nil {
		log.Fatalf("failed to attach kprobe/tcp_connect: %v", err)
	}
	defer kpTcpConnect.Close()

	krpAccept, err := link.Kretprobe("inet_csk_accept", objs.KpInetCskAcceptRet, nil)
	if err != nil {
		log.Fatalf("failed to attach kretprobe/inet_csk_accept: %v", err)
	}
	defer krpAccept.Close()

	kpTcpClose, err := link.Kprobe("tcp_close", objs.KpTcpClose, nil)
	if err != nil {
		log.Fatalf("failed to attach kprobe/tcp_close: %v", err)
	}
	defer kpTcpClose.Close()

	kpUdpSend, err := link.Kprobe("udp_sendmsg", objs.KpUdpSendmsg, nil)
	if err != nil {
		log.Fatalf("failed to attach kprobe/udp_sendmsg: %v", err)
	}
	defer kpUdpSend.Close()

	kpUdpDestroy, err := link.Kprobe("udp_destroy_sock", objs.KpUdpDestroySock, nil)
	if err != nil {
		log.Fatalf("failed to attach kprobe/udp_destroy_sock: %v", err)
	}
	defer kpUdpDestroy.Close()

	// Attach cgroup_skb programs
	cgEgress, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupP,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.CgroupSkbEgress,
	})
	if err != nil {
		log.Fatalf("failed to attach cgroup_skb/egress: %v", err)
	}
	defer cgEgress.Close()

	cgIngress, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupP,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: objs.CgroupSkbIngress,
	})
	if err != nil {
		log.Fatalf("failed to attach cgroup_skb/ingress: %v", err)
	}
	defer cgIngress.Close()

	// Open ring buffer reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("failed to open ring buffer reader: %v", err)
	}
	defer rd.Close()

	// Open pcapng output
	writer, err := pcapng.NewWriter(outFile, pcapng.LinkTypeRawIPv4, uint32(snapLen))
	if err != nil {
		log.Fatalf("failed to create pcapng file: %v", err)
	}
	defer writer.Close()

	// Sample ID tracking (per-flow grouping by normalized 5-tuple)
	sampleIDs := make(map[flowKey]uint64)
	flowComm := make(map[flowKey]string)
	nextSampleID := uint64(0)

	getSampleID := func(fk flowKey, comm string) uint64 {
		if id, ok := sampleIDs[fk]; ok {
			return id
		}
		id := nextSampleID
		nextSampleID++
		sampleIDs[fk] = id
		flowComm[fk] = comm
		return id
	}

	// Cgroup resolver
	var cgRes *cgroupResolver
	if cgroupInfo {
		cgRes = newCgroupResolver()
	}

	// Signal handling
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	var st captureStats

	go func() {
		<-sig
		log.Println("shutting down...")
		rd.Close()
	}()

	log.Printf("capturing to %s (snap_len=%d, cgroup=%s)", outFile, snapLen, cgroupP)
	if allow != "" {
		log.Printf("allow list: %s", allow)
	}
	if deny != "" {
		log.Printf("deny list: %s", deny)
	}
	if !includeDNS && !resolve {
		log.Println("DNS traffic (port 53) filtered out (use --include-dns to capture)")
	} else if !includeDNS && resolve {
		log.Println("DNS traffic (port 53) used for resolution but not written to output")
	}
	log.Println("press Ctrl+C to stop")

	// Main event loop
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Printf("ring buffer read error: %v", err)
			continue
		}

		raw := record.RawSample
		if len(raw) < hostHdrSize {
			st.packetsDropped++
			continue
		}

		var hdr pktEventHdr
		if err := binary.Read(bytes.NewReader(raw[:hostHdrSize]), binary.LittleEndian, &hdr); err != nil {
			st.packetsDropped++
			continue
		}

		dataEnd := hostHdrSize + int(hdr.CapLen)
		if dataEnd > len(raw) {
			dataEnd = len(raw)
		}
		pktData := raw[hostHdrSize:dataEnd]

		comm := strings.TrimRight(string(hdr.Comm[:]), "\x00")
		if comm == "" {
			comm = "_unknown"
			st.packetsUnknown++
		}

		// Resolution: process DNS responses and extract SNI
		isDNS := false
		if res != nil {
			isDNS = res.processPacket(pktData)
		}

		// Skip writing DNS packets unless user explicitly wants them
		if isDNS && !includeDNS {
			continue
		}

		fk, ok := parseFlowKey(pktData)
		if !ok {
			st.packetsDropped++
			continue
		}
		sid := getSampleID(fk, comm)

		// Label format: s=<id>,proc=<name>,dir=<direction>[,dst=<domain>]
		// If LAN CIDRs are configured, classify as lan2wan/wan2lan/lan2lan/wan2wan.
		// Otherwise fall back to e(gress)/i(ngress) relative to the process.
		var dir string
		if len(lanCIDRs) > 0 && len(pktData) >= 20 {
			dir = classifyDirection(pktData, lanCIDRs)
		} else {
			dir = "lan2wan"
			if hdr.Direction == 0 {
				dir = "wan2lan"
			}
		}
		comment := fmt.Sprintf("s=%d,proc=%s,dir=%s", sid, comm, dir)
		if res != nil {
			if domain := res.resolveLabel(pktData); domain != "" {
				comment += ",dst=" + domain
			}
		}
		if cgRes != nil && hdr.CgroupId != 0 {
			cgPath := cgRes.resolve(hdr.CgroupId, hdr.Pid)
			comment += ",cgroup=" + cgPath
		}

		wallNs := int64(hdr.TimestampNs) + bootOffset
		wallUs := uint64(wallNs / 1000)

		if err := writer.WritePacket(wallUs, pktData, hdr.PktLen, comment); err != nil {
			log.Printf("write error: %v", err)
			st.packetsDropped++
			continue
		}
		st.packetsCapt++
	}

	fmt.Println()
	fmt.Println("--- pcapml capture stats ---")
	fmt.Printf("packets captured:  %d\n", st.packetsCapt)
	fmt.Printf("packets dropped:   %d\n", st.packetsDropped)
	fmt.Printf("unique flows:      %d\n", len(sampleIDs))
	if len(sampleIDs) > 0 {
		fmt.Println("sample ID mapping:")
		for fk, id := range sampleIDs {
			fmt.Printf("  %d -> %s (%d.%d.%d.%d:%d <-> %d.%d.%d.%d:%d proto=%d)\n",
				id, flowComm[fk],
				fk.ipA[0], fk.ipA[1], fk.ipA[2], fk.ipA[3], fk.portA,
				fk.ipB[0], fk.ipB[1], fk.ipB[2], fk.ipB[3], fk.portB,
				fk.proto)
		}
	}
	fmt.Printf("output: %s\n", outFile)
}

// classifyDirection determines the network-topology direction of a packet
// based on whether the source and destination IPs are within the configured
// LAN CIDRs. pkt must be a raw IPv4 packet (at least 20 bytes).
func classifyDirection(pkt []byte, lanCIDRs []*net.IPNet) string {
	srcIP := net.IP(pkt[12:16])
	dstIP := net.IP(pkt[16:20])

	srcLocal := ipInNets(srcIP, lanCIDRs)
	dstLocal := ipInNets(dstIP, lanCIDRs)

	switch {
	case srcLocal && dstLocal:
		return "lan2lan"
	case srcLocal && !dstLocal:
		return "lan2wan"
	case !srcLocal && dstLocal:
		return "wan2lan"
	default:
		return "wan2wan"
	}
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// detectLANCIDRs discovers LAN subnets from the host's network interfaces.
// It returns the subnet CIDR for each non-loopback interface that has an
// IPv4 address.
func detectLANCIDRs() []*net.IPNet {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var cidrs []*net.IPNet
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.IP.To4() == nil {
				continue // skip IPv6
			}
			// Mask to get the network address
			network := &net.IPNet{
				IP:   ipNet.IP.Mask(ipNet.Mask),
				Mask: ipNet.Mask,
			}
			cidrs = append(cidrs, network)
		}
	}
	return cidrs
}
