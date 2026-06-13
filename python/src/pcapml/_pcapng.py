# SPDX-License-Identifier: Apache-2.0
"""Pure-Python streaming reader for the pcapng blocks pcapml emits.

This module knows nothing about pcapml labels; it just yields packets with the
raw per-packet comment string. Higher layers parse the comment. Only the block
types pcapml writes are interpreted (SHB, IDB, EPB); anything else is skipped.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator, List, Optional, Union

# Block type codes.
SECTION_HEADER = 0x0A0D0D0A
INTERFACE_DESC = 0x00000001
ENHANCED_PACKET = 0x00000006
BYTE_ORDER_MAGIC = 0x1A2B3C4D

# Option codes.
OPT_END = 0
OPT_COMMENT = 1
IDB_OPT_TSRESOL = 9

# The 4 bytes of the Section Header Block type are byte-order independent, which
# is exactly how a reader bootstraps endianness for the rest of the section.
_SHB_MAGIC_BYTES = b"\x0a\x0d\x0d\x0a"


@dataclass
class Interface:
    """An Interface Description Block: link type and timestamp resolution."""

    link_type: int
    snap_len: int
    ts_resol: float = 1e-6  # seconds per timestamp tick (pcapng default: microsec)


@dataclass
class Packet:
    """One Enhanced Packet Block with its pcapml comment."""

    interface_id: int
    ts_ticks: int
    cap_len: int
    orig_len: int
    data: bytes
    comment: str
    link_type: int
    ts_resol: float

    @property
    def timestamp(self) -> float:
        """Capture time as POSIX seconds (float)."""
        return self.ts_ticks * self.ts_resol

    @property
    def ts_nanos(self) -> int:
        """Capture time as integer nanoseconds (loss-free for ns/us/ms resolutions)."""
        return int(round(self.ts_ticks * self.ts_resol * 1e9))


def _read_exact(f: BinaryIO, n: int) -> Optional[bytes]:
    """Read exactly n bytes or return None at a clean EOF."""
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = f.read(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _ts_resol_from_byte(v: int) -> float:
    """Decode an if_tsresol option byte into seconds-per-tick."""
    if v & 0x80:
        return 2.0 ** -(v & 0x7F)
    return 10.0 ** -v


def _iter_options(body: bytes, off: int, le: str):
    """Yield (code, value_bytes) for the options region starting at off."""
    n = len(body)
    while off + 4 <= n:
        code, length = struct.unpack_from(le + "HH", body, off)
        if code == OPT_END:
            break
        start = off + 4
        end = start + length
        if end > n:
            break
        yield code, body[start:end]
        off = end + ((4 - length % 4) % 4)  # options are padded to 32 bits


def iter_packets(source: Union[str, BinaryIO]) -> Iterator[Packet]:
    """Yield :class:`Packet` for every Enhanced Packet Block in a pcapng stream.

    ``source`` may be a filesystem path or an already-open binary file object.
    """
    if isinstance(source, str):
        with open(source, "rb") as f:
            yield from _iter_packets(f)
    else:
        yield from _iter_packets(source)


def _iter_packets(f: BinaryIO) -> Iterator[Packet]:
    le = "<"
    interfaces: List[Interface] = []

    while True:
        type_bytes = _read_exact(f, 4)
        if type_bytes is None:
            return

        if type_bytes == _SHB_MAGIC_BYTES:
            # Section Header Block: re-establish endianness and reset interfaces.
            len_bytes = _read_exact(f, 4)
            magic_bytes = _read_exact(f, 4)
            if len_bytes is None or magic_bytes is None:
                return
            le = "<" if struct.unpack("<I", magic_bytes)[0] == BYTE_ORDER_MAGIC else ">"
            block_len = struct.unpack(le + "I", len_bytes)[0]
            # 12 bytes already consumed (type + length + magic).
            if _read_exact(f, block_len - 12) is None:
                return
            interfaces = []
            continue

        len_bytes = _read_exact(f, 4)
        if len_bytes is None:
            return
        block_type = struct.unpack(le + "I", type_bytes)[0]
        block_len = struct.unpack(le + "I", len_bytes)[0]
        if block_len < 12:
            return  # corrupt: length must cover type+length+trailer
        rest = _read_exact(f, block_len - 8)
        if rest is None:
            return
        body = rest[:-4]  # drop the trailing redundant block length

        if block_type == INTERFACE_DESC:
            interfaces.append(_parse_idb(body, le))
        elif block_type == ENHANCED_PACKET:
            pkt = _parse_epb(body, le, interfaces)
            if pkt is not None:
                yield pkt
        # Other block types (SPB, NRB, ISB, ...) carry no pcapml labels: skip.


def _parse_idb(body: bytes, le: str) -> Interface:
    link_type, _reserved, snap_len = struct.unpack_from(le + "HHI", body, 0)
    ts_resol = 1e-6
    for code, val in _iter_options(body, 8, le):
        if code == IDB_OPT_TSRESOL and val:
            ts_resol = _ts_resol_from_byte(val[0])
    return Interface(link_type=link_type, snap_len=snap_len, ts_resol=ts_resol)


def _parse_epb(body: bytes, le: str, interfaces: List[Interface]) -> Optional[Packet]:
    if len(body) < 20:
        return None
    iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack_from(le + "IIIII", body, 0)
    data = body[20 : 20 + cap_len]
    if len(data) < cap_len:
        return None

    opt_off = 20 + cap_len + ((4 - cap_len % 4) % 4)
    comment = ""
    for code, val in _iter_options(body, opt_off, le):
        if code == OPT_COMMENT:
            comment = val.rstrip(b"\x00").decode("utf-8", "replace")
            break

    if 0 <= iface_id < len(interfaces):
        iface = interfaces[iface_id]
    else:
        iface = Interface(link_type=0, snap_len=0)

    return Packet(
        interface_id=iface_id,
        ts_ticks=(ts_high << 32) | ts_low,
        cap_len=cap_len,
        orig_len=orig_len,
        data=data,
        comment=comment,
        link_type=iface.link_type,
        ts_resol=iface.ts_resol,
    )
