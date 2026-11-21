# SPDX-License-Identifier: Apache-2.0
"""Timestamps in files from older pcapml writers (nprint/pcapml#15).

The nPrint datasets declare no if_tsresol and store classic pcap time
(seconds in the high 32 bits, microseconds in the low 32). Read as plain
microseconds that overflows int64 nanoseconds and used to crash
read_pcapml() with OutOfBoundsDatetime.
"""
import struct

import pandas as pd

import pcapml

# A minimal RAW-IPv4 UDP packet: 10.0.0.1:1234 -> 8.8.8.8:53, 28 bytes.
PKT = bytes.fromhex("4500001c00000000401100000a00000108080808" "04d2003500080000")


def _block(btype, body):
    body += b"\x00" * ((4 - len(body) % 4) % 4)
    n = 12 + len(body)
    return struct.pack("<II", btype, n) + body + struct.pack("<I", n)


def _opt(code, val):
    return struct.pack("<HH", code, len(val)) + val + b"\x00" * ((4 - len(val) % 4) % 4)


def _pcapng(path, ticks, comment="7,china", tsresol=None):
    shb = _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb_opts = (_opt(9, bytes([tsresol])) + _opt(0, b"")) if tsresol is not None else b""
    idb = _block(0x1, struct.pack("<HHI", 101, 0, 65535) + idb_opts)
    epb = _block(0x6, struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(PKT), len(PKT))
                 + PKT + b"\x00" * ((4 - len(PKT) % 4) % 4)
                 + _opt(1, comment.encode()) + _opt(0, b""))
    path.write_bytes(shb + idb + epb)
    return str(path)


def test_legacy_seconds_microseconds(tmp_path):
    # Packet from the nPrint country-of-origin dataset: 2017-09-29 04:37:19.128391 UTC.
    ticks = (1506659839 << 32) | 128391
    f = _pcapng(tmp_path / "legacy_secusec.pcapng", ticks)
    df = pcapml.read_pcapml(f)
    assert df["timestamp"].iloc[0] == pd.Timestamp("2017-09-29 04:37:19.128391", tz="UTC")
    assert df["label"].iloc[0] == "china" and df["sample_id"].iloc[0] == "7"
    assert df["src_ip"].iloc[0] == "10.0.0.1" and df["dst_port"].iloc[0] == 53
    s = next(pcapml.samples(f))
    assert s.label == "china" and len(s) == 1


def test_plain_microseconds_unchanged(tmp_path):
    us = 1_506_659_839_128_391  # in range as microseconds: decoded as before
    df = pcapml.read_pcapml(_pcapng(tmp_path / "usec.pcapng", us))
    assert df["timestamp"].iloc[0] == pd.Timestamp("2017-09-29 04:37:19.128391", tz="UTC")


def test_explicit_nanosecond_resolution(tmp_path):
    ns = 1_506_659_839_128_391_000
    df = pcapml.read_pcapml(_pcapng(tmp_path / "nsec.pcapng", ns, tsresol=9))
    assert df["timestamp"].iloc[0] == pd.Timestamp("2017-09-29 04:37:19.128391", tz="UTC")


def test_undecodable_timestamp_is_nat_not_crash(tmp_path):
    ticks = 0xFFFFFFFF_FFFFFFFF  # low word >= 1e6 and too big for nanoseconds
    df = pcapml.read_pcapml(_pcapng(tmp_path / "bad.pcapng", ticks))
    assert len(df) == 1 and pd.isna(df["timestamp"].iloc[0])
    assert df["label"].iloc[0] == "china"
