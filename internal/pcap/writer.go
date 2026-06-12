// SPDX-License-Identifier: Apache-2.0

package pcap

import (
	"encoding/binary"
	"os"
)

const (
	pcapMagic      = 0xA1B2C3D4
	pcapVersionMaj = 2
	pcapVersionMin = 4
	defaultSnapLen = 65535
)

// Writer writes plain pcap files.
type Writer struct {
	f      *os.File
	le     binary.ByteOrder
	closed bool
}

// NewWriter creates a new pcap file with a global header.
func NewWriter(filename string, linkType uint16) (*Writer, error) {
	f, err := os.Create(filename)
	if err != nil {
		return nil, err
	}

	w := &Writer{f: f, le: binary.LittleEndian}
	if err := w.writeGlobalHeader(linkType); err != nil {
		f.Close()
		return nil, err
	}

	return w, nil
}

// WritePacket writes a pcap packet record.
// tsSec and tsUsec are seconds and microseconds since epoch.
func (w *Writer) WritePacket(tsSec, tsUsec uint32, capLen, origLen uint32, data []byte) error {
	if err := binary.Write(w.f, w.le, tsSec); err != nil {
		return err
	}
	if err := binary.Write(w.f, w.le, tsUsec); err != nil {
		return err
	}
	if err := binary.Write(w.f, w.le, capLen); err != nil {
		return err
	}
	if err := binary.Write(w.f, w.le, origLen); err != nil {
		return err
	}
	_, err := w.f.Write(data[:capLen])
	return err
}

func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	return w.f.Close()
}

func (w *Writer) writeGlobalHeader(linkType uint16) error {
	// pcap global header: magic, version_major, version_minor, thiszone, sigfigs, snaplen, network
	if err := binary.Write(w.f, w.le, uint32(pcapMagic)); err != nil {
		return err
	}
	if err := binary.Write(w.f, w.le, uint16(pcapVersionMaj)); err != nil {
		return err
	}
	if err := binary.Write(w.f, w.le, uint16(pcapVersionMin)); err != nil {
		return err
	}
	if err := binary.Write(w.f, w.le, int32(0)); err != nil { // thiszone
		return err
	}
	if err := binary.Write(w.f, w.le, uint32(0)); err != nil { // sigfigs
		return err
	}
	if err := binary.Write(w.f, w.le, uint32(defaultSnapLen)); err != nil { // snaplen
		return err
	}
	return binary.Write(w.f, w.le, uint32(linkType)) // network
}
