// SPDX-License-Identifier: Apache-2.0

package pcapng

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
)

// Block represents a parsed pcapng block.
type Block struct {
	Type    uint32
	RawData []byte // complete block bytes (including header and trailer)

	// Parsed fields for EPB blocks
	InterfaceID uint32
	TsHigh      uint32
	TsLow       uint32
	CapLen      uint32
	OrigLen     uint32
	PacketData  []byte
	Comment     string

	// Parsed fields for IDB blocks
	LinkType uint16
	SnapLen  uint32
}

// Reader reads pcapng files block by block.
type Reader struct {
	f  *os.File
	le binary.ByteOrder
}

// NewReader opens a pcapng file for reading.
func NewReader(filename string) (*Reader, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	return &Reader{f: f, le: binary.LittleEndian}, nil
}

// ReadBlock reads the next block from the file. Returns nil, io.EOF at end.
func (r *Reader) ReadBlock() (*Block, error) {
	// Read block type and length
	var blockType, blockLen uint32
	if err := binary.Read(r.f, r.le, &blockType); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("read block type: %w", err)
	}
	if err := binary.Read(r.f, r.le, &blockLen); err != nil {
		return nil, fmt.Errorf("read block length: %w", err)
	}

	if blockLen < BaseBlockLen {
		return nil, fmt.Errorf("invalid block length %d", blockLen)
	}

	// Allocate full block and read remaining bytes directly into it
	raw := make([]byte, blockLen)
	r.le.PutUint32(raw[0:4], blockType)
	r.le.PutUint32(raw[4:8], blockLen)
	if _, err := io.ReadFull(r.f, raw[8:]); err != nil {
		return nil, fmt.Errorf("read block body: %w", err)
	}

	b := &Block{
		Type:    blockType,
		RawData: raw,
	}

	// Parse based on block type
	body := raw[8:]
	switch blockType {
	case SectionHeaderType:
		// Nothing extra to parse for our purposes
	case InterfaceDescType:
		r.parseIDB(b, body)
	case EnhancedPacketType:
		r.parseEPB(b, body)
	}

	return b, nil
}

func (r *Reader) parseIDB(b *Block, body []byte) {
	if len(body) < InterfaceDescBodyLen+4 { // +4 for trailing length
		return
	}
	b.LinkType = r.le.Uint16(body[0:2])
	// body[2:4] = reserved
	b.SnapLen = r.le.Uint32(body[4:8])
}

func (r *Reader) parseEPB(b *Block, body []byte) {
	if len(body) < EnhancedPacketBodyLen+4 { // +4 for trailing length
		return
	}

	b.InterfaceID = r.le.Uint32(body[0:4])
	b.TsHigh = r.le.Uint32(body[4:8])
	b.TsLow = r.le.Uint32(body[8:12])
	b.CapLen = r.le.Uint32(body[12:16])
	b.OrigLen = r.le.Uint32(body[16:20])

	// Packet data starts at offset 20
	pktEnd := 20 + int(b.CapLen)
	if pktEnd > len(body)-4 { // -4 for trailing block length
		return
	}
	b.PacketData = body[20:pktEnd]

	// Skip packet padding
	pktPad := int(pad4(b.CapLen))
	optStart := pktEnd + pktPad

	// Parse options to find comment
	b.Comment = parseComment(body[optStart:len(body)-4], r.le)
}

// parseComment extracts the first comment option from an options region.
func parseComment(data []byte, le binary.ByteOrder) string {
	for len(data) >= OptionHeaderLen {
		code := le.Uint16(data[0:2])
		length := le.Uint16(data[2:4])

		if code == OptionEnd {
			break
		}

		if int(length) > len(data)-OptionHeaderLen {
			break
		}

		if code == OptionComment {
			return strings.TrimRight(string(data[OptionHeaderLen:OptionHeaderLen+int(length)]), "\x00")
		}

		// Skip this option + padding
		advance := OptionHeaderLen + int(length) + int(pad4(uint32(length)))
		if advance > len(data) {
			break
		}
		data = data[advance:]
	}
	return ""
}

// Timestamp returns the combined 64-bit microsecond timestamp.
func (b *Block) Timestamp() uint64 {
	return uint64(b.TsHigh)<<32 | uint64(b.TsLow)
}

// CommentVal extracts the value for a given key from a comma-separated
// key=value comment string. Returns "" if the key is not found.
func CommentVal(comment, key string) string {
	prefix := key + "="
	for _, field := range strings.Split(comment, ",") {
		if strings.HasPrefix(field, prefix) {
			return field[len(prefix):]
		}
	}
	return ""
}

// SampleID extracts the sample ID from the comment.
// Supports keyed format (s=<id>,...) and legacy positional format (<id>,...).
func (b *Block) SampleID() string {
	if b.Comment == "" {
		return ""
	}
	if v := CommentVal(b.Comment, "s"); v != "" {
		return v
	}
	// Legacy positional fallback: first comma-separated field
	if idx := strings.IndexByte(b.Comment, ','); idx >= 0 {
		return b.Comment[:idx]
	}
	return b.Comment
}

// Label extracts the label from the comment.
// Supports keyed format (proc=<label>,...) and legacy positional format (<id>,<label>,...).
func (b *Block) Label() string {
	if b.Comment == "" {
		return ""
	}
	if v := CommentVal(b.Comment, "proc"); v != "" {
		return v
	}
	if v := CommentVal(b.Comment, "dst"); v != "" {
		return v
	}
	// Legacy positional fallback: second comma-separated field
	if idx := strings.IndexByte(b.Comment, ','); idx >= 0 {
		rest := b.Comment[idx+1:]
		if idx2 := strings.IndexByte(rest, ','); idx2 >= 0 {
			return rest[:idx2]
		}
		return rest
	}
	return ""
}

func (r *Reader) Close() error {
	return r.f.Close()
}
