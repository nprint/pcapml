// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"
)

// domainEntry holds a resolved domain name and its expiry time.
type domainEntry struct {
	domain  string
	expires time.Time
}

// resolver tracks DNS responses and SNI to map IPs to domain names.
type resolver struct {
	mu      sync.RWMutex
	domains map[[4]byte]domainEntry // IP -> domain
}

func newResolver() *resolver {
	return &resolver{
		domains: make(map[[4]byte]domainEntry),
	}
}

// lookup returns the domain name for an IP, if known.
func (e *resolver) lookup(ip [4]byte) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	entry, ok := e.domains[ip]
	if !ok {
		return ""
	}
	if time.Now().After(entry.expires) {
		return "" // expired, will be cleaned up lazily
	}
	return entry.domain
}

// addMapping associates an IP with a domain name.
func (e *resolver) addMapping(ip [4]byte, domain string, ttl uint32) {
	if ttl == 0 {
		ttl = 300 // default 5 min TTL
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.domains[ip] = domainEntry{
		domain:  domain,
		expires: time.Now().Add(time.Duration(ttl) * time.Second),
	}
}

// processPacket handles DNS response parsing and SNI extraction for a packet.
// Returns true if the packet is DNS traffic.
func (e *resolver) processPacket(pktData []byte) bool {
	isDNS := e.processDNS(pktData)
	sni := extractSNI(pktData)
	if sni == "" {
		sni = extractQUICSNI(pktData)
	}
	if sni != "" && len(pktData) >= 20 {
		var dstIP [4]byte
		copy(dstIP[:], pktData[16:20])
		e.addMapping(dstIP, sni, 3600) // 1hr TTL for SNI
	}
	return isDNS
}

// resolveLabel returns the destination domain for a packet, if known.
// pkt is raw IPv4 (no link-layer header).
func (e *resolver) resolveLabel(pkt []byte) string {
	if len(pkt) < 20 {
		return ""
	}
	var dstIP [4]byte
	copy(dstIP[:], pkt[16:20])

	if domain := e.lookup(dstIP); domain != "" {
		return domain
	}

	// Also check source IP (for ingress packets, the server is the source)
	var srcIP [4]byte
	copy(srcIP[:], pkt[12:16])
	return e.lookup(srcIP)
}

// processDNS parses a DNS response and extracts IP->domain mappings.
// pkt is raw IPv4 (no link-layer header). Returns true if this is a DNS packet.
func (e *resolver) processDNS(pkt []byte) bool {
	if len(pkt) < 20 {
		return false
	}
	proto := pkt[9]
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return false
	}

	srcPort := binary.BigEndian.Uint16(pkt[ihl : ihl+2])
	dstPort := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])

	if srcPort != 53 && dstPort != 53 {
		return false
	}

	// Only parse responses (from port 53)
	if srcPort != 53 {
		return true // it's a DNS query, not a response — still DNS though
	}

	var dnsOffset int
	switch proto {
	case 17: // UDP
		if len(pkt) < ihl+8 {
			return true
		}
		dnsOffset = ihl + 8
	case 6: // TCP (rare for DNS, skip for now)
		return true
	default:
		return false
	}

	if len(pkt) < dnsOffset+12 {
		return true
	}

	dns := pkt[dnsOffset:]
	parseDNSResponse(e, dns)
	return true
}

// parseDNSResponse extracts A record answers from a DNS response payload.
func parseDNSResponse(e *resolver, dns []byte) {
	if len(dns) < 12 {
		return
	}

	flags := binary.BigEndian.Uint16(dns[2:4])
	isResponse := flags&0x8000 != 0
	if !isResponse {
		return
	}

	qdCount := binary.BigEndian.Uint16(dns[4:6])
	anCount := binary.BigEndian.Uint16(dns[6:8])

	if anCount == 0 {
		return
	}

	// Skip header
	off := 12

	// Skip question section
	for i := 0; i < int(qdCount); i++ {
		var err bool
		off, err = skipDNSName(dns, off)
		if err {
			return
		}
		off += 4 // QTYPE + QCLASS
		if off > len(dns) {
			return
		}
	}

	// Collect the query name (first question) for CNAME resolution
	queryName := ""
	if qdCount > 0 {
		qOff := 12
		queryName, _ = readDNSName(dns, qOff)
	}

	// Build CNAME chain: target -> canonical name
	cnameMap := make(map[string]string)

	// Parse answer section
	for i := 0; i < int(anCount); i++ {
		name, newOff := readDNSName(dns, off)
		if newOff < 0 {
			return
		}
		off = newOff

		if off+10 > len(dns) {
			return
		}

		rtype := binary.BigEndian.Uint16(dns[off : off+2])
		// rclass at off+2
		ttl := binary.BigEndian.Uint32(dns[off+4 : off+8])
		rdLength := binary.BigEndian.Uint16(dns[off+8 : off+10])
		off += 10

		if off+int(rdLength) > len(dns) {
			return
		}

		switch rtype {
		case 1: // A record
			if rdLength == 4 {
				var ip [4]byte
				copy(ip[:], dns[off:off+4])
				domain := resolveCNAME(cnameMap, name, queryName)
				e.addMapping(ip, domain, ttl)
			}
		case 5: // CNAME
			target, _ := readDNSName(dns, off)
			if target != "" {
				cnameMap[strings.ToLower(target)] = name
			}
		}

		off += int(rdLength)
	}
}

// resolveCNAME follows the CNAME chain back to the original query name.
func resolveCNAME(cnameMap map[string]string, name string, queryName string) string {
	if queryName != "" {
		return strings.TrimSuffix(strings.ToLower(queryName), ".")
	}
	// Walk CNAME chain (max 10 hops to prevent loops)
	current := strings.ToLower(name)
	for i := 0; i < 10; i++ {
		if canonical, ok := cnameMap[current]; ok {
			current = strings.ToLower(canonical)
		} else {
			break
		}
	}
	return strings.TrimSuffix(current, ".")
}

// readDNSName reads a DNS name at offset, handling compression pointers.
// Returns the name and the new offset after the name, or ("", -1) on error.
func readDNSName(dns []byte, off int) (string, int) {
	var parts []string
	jumped := false
	savedOff := -1
	maxJumps := 10

	for i := 0; i < maxJumps*20; i++ {
		if off >= len(dns) {
			return "", -1
		}

		length := int(dns[off])
		if length == 0 {
			off++
			break
		}

		if length&0xC0 == 0xC0 {
			if off+1 >= len(dns) {
				return "", -1
			}
			ptr := int(binary.BigEndian.Uint16(dns[off:off+2])) & 0x3FFF
			if !jumped {
				savedOff = off + 2
			}
			jumped = true
			off = ptr
			maxJumps--
			if maxJumps <= 0 {
				return "", -1
			}
			continue
		}

		off++
		if off+length > len(dns) {
			return "", -1
		}
		parts = append(parts, string(dns[off:off+length]))
		off += length
	}

	if jumped {
		off = savedOff
	}

	return strings.Join(parts, "."), off
}

// skipDNSName skips a DNS name at offset, returning the new offset.
func skipDNSName(dns []byte, off int) (int, bool) {
	for {
		if off >= len(dns) {
			return off, true
		}
		length := int(dns[off])
		if length == 0 {
			return off + 1, false
		}
		if length&0xC0 == 0xC0 {
			return off + 2, false
		}
		off += 1 + length
	}
}

// extractSNI parses a TLS ClientHello from a raw IPv4 packet and returns
// the Server Name Indication value, if present.
func extractSNI(pkt []byte) string {
	if len(pkt) < 20 {
		return ""
	}
	proto := pkt[9]
	if proto != 6 { // TCP only
		return ""
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl+20 {
		return ""
	}

	// TCP header
	tcpHdr := pkt[ihl:]
	dataOff := int(tcpHdr[12]>>4) * 4
	if dataOff < 20 || len(pkt) < ihl+dataOff {
		return ""
	}

	payload := pkt[ihl+dataOff:]
	return parseTLSClientHelloSNI(payload)
}

// parseTLSClientHelloSNI extracts the SNI from a TLS record containing a ClientHello.
func parseTLSClientHelloSNI(data []byte) string {
	// TLS record header: type(1) + version(2) + length(2)
	if len(data) < 5 {
		return ""
	}
	if data[0] != 0x16 { // Handshake
		return ""
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	data = data[5:]
	if len(data) < recordLen {
		return ""
	}
	data = data[:recordLen]

	// Handshake header: type(1) + length(3)
	if len(data) < 4 {
		return ""
	}
	if data[0] != 0x01 { // ClientHello
		return ""
	}
	handshakeLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	data = data[4:]
	if len(data) < handshakeLen {
		return ""
	}
	data = data[:handshakeLen]

	// ClientHello: version(2) + random(32) = 34
	if len(data) < 34 {
		return ""
	}
	data = data[34:]

	// Session ID: length(1) + data
	if len(data) < 1 {
		return ""
	}
	sessIDLen := int(data[0])
	data = data[1:]
	if len(data) < sessIDLen {
		return ""
	}
	data = data[sessIDLen:]

	// Cipher suites: length(2) + data
	if len(data) < 2 {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < csLen {
		return ""
	}
	data = data[csLen:]

	// Compression methods: length(1) + data
	if len(data) < 1 {
		return ""
	}
	compLen := int(data[0])
	data = data[1:]
	if len(data) < compLen {
		return ""
	}
	data = data[compLen:]

	// Extensions: length(2) + data
	if len(data) < 2 {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < extLen {
		return ""
	}
	data = data[:extLen]

	// Walk extensions looking for SNI (type 0x0000)
	for len(data) >= 4 {
		extType := binary.BigEndian.Uint16(data[:2])
		extDataLen := int(binary.BigEndian.Uint16(data[2:4]))
		data = data[4:]
		if len(data) < extDataLen {
			return ""
		}

		if extType == 0 { // server_name
			sniData := data[:extDataLen]
			return parseSNIExtension(sniData)
		}

		data = data[extDataLen:]
	}

	return ""
}

// parseSNIExtension extracts the hostname from a server_name extension.
func parseSNIExtension(data []byte) string {
	// SNI list length(2)
	if len(data) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < listLen {
		return ""
	}

	// Walk entries: type(1) + length(2) + name
	for len(data) >= 3 {
		nameType := data[0]
		nameLen := int(binary.BigEndian.Uint16(data[1:3]))
		data = data[3:]
		if len(data) < nameLen {
			return ""
		}
		if nameType == 0 { // host_name
			name := string(data[:nameLen])
			// Validate it looks like a hostname
			if net.ParseIP(name) == nil && len(name) > 0 {
				return strings.ToLower(name)
			}
		}
		data = data[nameLen:]
	}

	return ""
}
