// SPDX-License-Identifier: Apache-2.0

//go:build ebpf

package cmd

import (
	"bytes"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

const (
	maxCommLen = 16
	maxPktLen  = 1500

	// Host mode header: includes cgroup_id (56 bytes)
	hostHdrSize = 8 + 4 + 4 + 4 + 4 + 1 + 3 + 16 + 4 + 8 // 56 bytes

	// Gateway mode header: no cgroup_id (44 bytes)
	gwHdrSize = 8 + 4 + 4 + 4 + 4 + 1 + 3 + 16 // 44 bytes
)

// pktEventHdr is the host-mode event header (matches bpf/pcapml.bpf.c pkt_event).
type pktEventHdr struct {
	TimestampNs uint64
	Pid         uint32
	Uid         uint32
	PktLen      uint32
	CapLen      uint32
	Direction   uint8
	Pad         [3]uint8
	Comm        [maxCommLen]byte
	Pad2        uint32
	CgroupId    uint64
}

// gwPktEventHdr is the gateway-mode event header (matches bpf/gateway.bpf.c pkt_event).
type gwPktEventHdr struct {
	TimestampNs uint64
	Pid         uint32
	Uid         uint32
	PktLen      uint32
	CapLen      uint32
	Direction   uint8
	Pad         [3]uint8
	Comm        [maxCommLen]byte
}

type captureStats struct {
	packetsCapt    uint64
	packetsDropped uint64
	packetsUnknown uint64
	eventsReceived uint64
}

// flowKey is a normalized 5-tuple used to group packets into flows.
// The IP/port pairs are ordered so both directions of a flow match.
type flowKey struct {
	ipA, ipB     [4]byte
	portA, portB uint16
	proto        uint8
}

// parseFlowKey extracts a normalized 5-tuple from a raw IPv4 packet.
func parseFlowKey(pkt []byte) (flowKey, bool) {
	var fk flowKey
	if len(pkt) < 20 {
		return fk, false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl+4 {
		return fk, false
	}
	fk.proto = pkt[9]
	var srcIP, dstIP [4]byte
	copy(srcIP[:], pkt[12:16])
	copy(dstIP[:], pkt[16:20])
	srcPort := uint16(pkt[ihl])<<8 | uint16(pkt[ihl+1])
	dstPort := uint16(pkt[ihl+2])<<8 | uint16(pkt[ihl+3])
	// Normalize: smaller IP:port pair first so both directions match
	if bytes.Compare(srcIP[:], dstIP[:]) > 0 ||
		(bytes.Equal(srcIP[:], dstIP[:]) && srcPort > dstPort) {
		fk.ipA, fk.ipB = dstIP, srcIP
		fk.portA, fk.portB = dstPort, srcPort
	} else {
		fk.ipA, fk.ipB = srcIP, dstIP
		fk.portA, fk.portB = srcPort, dstPort
	}
	return fk, true
}

func getBootTimeOffset() (int64, error) {
	var bootTs unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &bootTs); err != nil {
		return 0, fmt.Errorf("clock_gettime BOOTTIME: %w", err)
	}
	bootNs := int64(bootTs.Sec)*1e9 + int64(bootTs.Nsec)
	wallNs := time.Now().UnixNano()
	return wallNs - bootNs, nil
}
