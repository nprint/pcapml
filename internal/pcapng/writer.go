// SPDX-License-Identifier: Apache-2.0

package pcapng

import (
	"encoding/binary"
	"os"
)

const (
	SectionHeaderType     = 0x0A0D0D0A
	InterfaceDescType     = 0x00000001
	EnhancedPacketType    = 0x00000006
	ByteOrderMagic        = 0x1A2B3C4D
	OptionComment         = 1
	OptionEnd             = 0
	LinkTypeRawIPv4       = 101 // LINKTYPE_RAW
	LinkTypeEthernet      = 1   // LINKTYPE_ETHERNET
	VersionMajor          = 1
	VersionMinor          = 0
	BaseBlockLen          = 12 // type(4) + length(4) + trailing_length(4)
	SectionHeaderBodyLen  = 16 // magic(4) + major(2) + minor(2) + section_len(8)
	InterfaceDescBodyLen  = 8  // link_type(2) + reserved(2) + snap_len(4)
	EnhancedPacketBodyLen = 20 // iface_id(4) + ts_high(4) + ts_low(4) + cap_len(4) + orig_len(4)
	OptionHeaderLen       = 4  // code(2) + length(2)
)

// Writer writes pcapng files with per-packet comment labels.
type Writer struct {
	f      *os.File
	le     binary.ByteOrder
	closed bool
}

// NewWriter creates a new pcapng file with SHB and IDB headers.
func NewWriter(filename string, linkType uint16, snapLen uint32) (*Writer, error) {
	f, err := os.Create(filename)
	if err != nil {
		return nil, err
	}

	w := &Writer{f: f, le: binary.LittleEndian}

	if err := w.writeSectionHeader(); err != nil {
		f.Close()
		return nil, err
	}
	if err := w.writeInterfaceDesc(linkType, snapLen); err != nil {
		f.Close()
		return nil, err
	}

	return w, nil
}

// WriteInterfaceDesc writes an additional Interface Description Block.
// Useful when the input has multiple link types (e.g., split/label operations).
func (w *Writer) WriteInterfaceDesc(linkType uint16, snapLen uint32) error {
	return w.writeInterfaceDesc(linkType, snapLen)
}

// WritePacket writes an Enhanced Packet Block with a comment option.
func (w *Writer) WritePacket(tsUsec uint64, data []byte, origLen uint32, comment string) error {
	capLen := uint32(len(data))
	pktPadLen := pad4(capLen)
	commentBytes := []byte(comment)
	commentPadLen := pad4(uint32(len(commentBytes)))

	blockLen := uint32(BaseBlockLen + EnhancedPacketBodyLen +
		capLen + pktPadLen +
		OptionHeaderLen + uint32(len(commentBytes)) + commentPadLen +
		OptionHeaderLen)

	tsHigh := uint32(tsUsec >> 32)
	tsLow := uint32(tsUsec & 0xFFFFFFFF)

	if err := w.writeU32(EnhancedPacketType); err != nil {
		return err
	}
	if err := w.writeU32(blockLen); err != nil {
		return err
	}
	if err := w.writeU32(0); err != nil { // interface_id
		return err
	}
	if err := w.writeU32(tsHigh); err != nil {
		return err
	}
	if err := w.writeU32(tsLow); err != nil {
		return err
	}
	if err := w.writeU32(capLen); err != nil {
		return err
	}
	if err := w.writeU32(origLen); err != nil {
		return err
	}

	if _, err := w.f.Write(data); err != nil {
		return err
	}
	if err := w.writePad(pktPadLen); err != nil {
		return err
	}

	if err := w.writeU16(OptionComment); err != nil {
		return err
	}
	if err := w.writeU16(uint16(len(commentBytes))); err != nil {
		return err
	}
	if _, err := w.f.Write(commentBytes); err != nil {
		return err
	}
	if err := w.writePad(commentPadLen); err != nil {
		return err
	}

	if err := w.writeU16(OptionEnd); err != nil {
		return err
	}
	if err := w.writeU16(0); err != nil {
		return err
	}

	return w.writeU32(blockLen)
}

// WriteRawBlock writes a pre-serialized block (used by sort to copy blocks).
func (w *Writer) WriteRawBlock(data []byte) error {
	_, err := w.f.Write(data)
	return err
}

func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	return w.f.Close()
}

func (w *Writer) writeSectionHeader() error {
	blockLen := uint32(BaseBlockLen + SectionHeaderBodyLen)

	if err := w.writeU32(SectionHeaderType); err != nil {
		return err
	}
	if err := w.writeU32(blockLen); err != nil {
		return err
	}
	if err := w.writeU32(ByteOrderMagic); err != nil {
		return err
	}
	if err := w.writeU16(VersionMajor); err != nil {
		return err
	}
	if err := w.writeU16(VersionMinor); err != nil {
		return err
	}
	if err := binary.Write(w.f, w.le, int64(-1)); err != nil {
		return err
	}
	return w.writeU32(blockLen)
}

func (w *Writer) writeInterfaceDesc(linkType uint16, snapLen uint32) error {
	blockLen := uint32(BaseBlockLen + InterfaceDescBodyLen)

	if err := w.writeU32(InterfaceDescType); err != nil {
		return err
	}
	if err := w.writeU32(blockLen); err != nil {
		return err
	}
	if err := w.writeU16(linkType); err != nil {
		return err
	}
	if err := w.writeU16(0); err != nil { // reserved
		return err
	}
	if err := w.writeU32(snapLen); err != nil {
		return err
	}
	return w.writeU32(blockLen)
}

func (w *Writer) writeU32(v uint32) error {
	return binary.Write(w.f, w.le, v)
}

func (w *Writer) writeU16(v uint16) error {
	return binary.Write(w.f, w.le, v)
}

var zeros [3]byte

func (w *Writer) writePad(n uint32) error {
	if n == 0 {
		return nil
	}
	_, err := w.f.Write(zeros[:n])
	return err
}

func pad4(n uint32) uint32 {
	if n%4 == 0 {
		return 0
	}
	return 4 - (n % 4)
}
