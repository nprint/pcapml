# SPDX-License-Identifier: Apache-2.0
"""Minimal pure-Python L3/L4 header decoding.

Just enough to populate the convenience columns (addresses, protocol, ports).
The full packet bytes are always preserved in the DataFrame for anyone who
wants a real dissector (dpkt, scapy, ...).
"""

from __future__ import annotations

import socket
import struct
from typing import Dict, Optional, Tuple

# Selected link types (https://www.tcpdump.org/linktypes.html).
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
# Some tools emit 12/14 for "raw IP"; treat them as raw too.
_RAW_IP_LINKTYPES = frozenset({LINKTYPE_RAW, 12, 14})

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
_VLAN_ETHERTYPES = frozenset({0x8100, 0x88A8, 0x9100})

IP_PROTO_NAMES: Dict[int, str] = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "IPv6-ICMP",
    89: "OSPF",
    132: "SCTP",
}

# IPv6 extension headers we skip over to reach the transport header.
_IPV6_EXT_HEADERS = frozenset({0, 43, 60})  # hop-by-hop, routing, dest-options

_EMPTY: Dict[str, Optional[object]] = {
    "src_ip": None,
    "dst_ip": None,
    "proto": None,
    "src_port": None,
    "dst_port": None,
}


def decode(data: bytes, link_type: int) -> Dict[str, Optional[object]]:
    """Decode L3/L4 fields from a raw packet. Never raises; unknowns are None."""
    try:
        payload, ethertype = _strip_l2(data, link_type)
        if payload is None:
            return dict(_EMPTY)
        if ethertype == ETHERTYPE_IPV4:
            return _decode_ipv4(payload)
        if ethertype == ETHERTYPE_IPV6:
            return _decode_ipv6(payload)
    except Exception:
        pass
    return dict(_EMPTY)


def _strip_l2(data: bytes, link_type: int) -> Tuple[Optional[bytes], Optional[int]]:
    """Return (l3_payload, ethertype), stripping any link-layer header."""
    if link_type == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None, None
        ethertype = struct.unpack_from("!H", data, 12)[0]
        off = 14
        while ethertype in _VLAN_ETHERTYPES and len(data) >= off + 4:
            ethertype = struct.unpack_from("!H", data, off + 2)[0]
            off += 4
        return data[off:], ethertype

    if link_type == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None, None
        return data[16:], struct.unpack_from("!H", data, 14)[0]

    if link_type in _RAW_IP_LINKTYPES or link_type == 0:
        return _raw_ip(data)

    return None, None


def _raw_ip(data: bytes) -> Tuple[Optional[bytes], Optional[int]]:
    """Infer IPv4 vs IPv6 from the version nibble of a raw IP packet."""
    if not data:
        return None, None
    version = data[0] >> 4
    if version == 4:
        return data, ETHERTYPE_IPV4
    if version == 6:
        return data, ETHERTYPE_IPV6
    return None, None


def _ip_str(raw: bytes, family: int) -> Optional[str]:
    try:
        return socket.inet_ntop(family, raw)
    except (OSError, ValueError):
        return None


def _ports(payload: bytes, off: int, proto: int) -> Tuple[Optional[int], Optional[int]]:
    if proto in (6, 17, 132) and len(payload) >= off + 4:  # TCP / UDP / SCTP
        src, dst = struct.unpack_from("!HH", payload, off)
        return src, dst
    return None, None


def _result(src_ip, dst_ip, proto, src_port, dst_port) -> Dict[str, Optional[object]]:
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "proto": IP_PROTO_NAMES.get(proto, str(proto)) if proto is not None else None,
        "src_port": src_port,
        "dst_port": dst_port,
    }


def _decode_ipv4(p: bytes) -> Dict[str, Optional[object]]:
    if len(p) < 20:
        return dict(_EMPTY)
    ihl = (p[0] & 0x0F) * 4
    proto = p[9]
    src_ip = _ip_str(p[12:16], socket.AF_INET)
    dst_ip = _ip_str(p[16:20], socket.AF_INET)
    src_port, dst_port = _ports(p, ihl, proto)
    return _result(src_ip, dst_ip, proto, src_port, dst_port)


def _decode_ipv6(p: bytes) -> Dict[str, Optional[object]]:
    if len(p) < 40:
        return dict(_EMPTY)
    next_hdr = p[6]
    src_ip = _ip_str(p[8:24], socket.AF_INET6)
    dst_ip = _ip_str(p[24:40], socket.AF_INET6)

    off = 40
    # Walk extension headers (each is 8-byte aligned via hdr_ext_len) to the
    # transport header. Fragment headers (44) are a fixed 8 bytes.
    while next_hdr in _IPV6_EXT_HEADERS or next_hdr == 44:
        if off + 2 > len(p):
            return _result(src_ip, dst_ip, None, None, None)
        ext_next = p[off]
        ext_len = 8 if next_hdr == 44 else (p[off + 1] + 1) * 8
        next_hdr = ext_next
        off += ext_len

    src_port, dst_port = _ports(p, off, next_hdr)
    return _result(src_ip, dst_ip, next_hdr, src_port, dst_port)
