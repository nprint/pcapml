# SPDX-License-Identifier: Apache-2.0
import os

import pandas as pd
import pytest

import pcapml

DATA = os.path.join(os.path.dirname(__file__), "data")
KEYED = os.path.join(DATA, "keyed.pcapng")    # linktype 101 (RAW), keyed comments
LEGACY = os.path.join(DATA, "legacy.pcapng")  # linktype 1 (Ethernet), positional


def test_parse_comment_keyed():
    sid, label, direction, dst, meta = pcapml.parse_comment(
        "s=0,proc=curl,dir=lan2wan,dst=example.com"
    )
    assert sid == "0"
    assert label == "curl"
    assert direction == "lan2wan"
    assert dst == "example.com"
    assert meta == {"s": "0", "proc": "curl", "dir": "lan2wan", "dst": "example.com"}


def test_parse_comment_legacy_positional():
    sid, label, direction, dst, meta = pcapml.parse_comment("18205618432581910911,windows-10")
    assert sid == "18205618432581910911"  # exceeds int64; kept as string
    assert label == "windows-10"
    assert direction is None
    assert dst is None
    assert meta == {}


def test_read_keyed_columns_and_decode():
    df = pcapml.read_pcapml(KEYED)
    assert list(df.columns) == pcapml.COLUMNS
    assert len(df) == 9
    assert (df["sample_id"] == "0").all()
    assert (df["label"] == "curl").all()
    assert set(df["direction"]) <= {"lan2wan", "wan2lan"}
    assert (df["dst"] == "example.com").all()
    # RAW IPv4 packets must decode to addresses + protocol.
    assert df["src_ip"].notna().all()
    assert set(df["proto"]) <= {"TCP", "UDP", "ICMP"}
    assert pd.api.types.is_datetime64_any_dtype(df["timestamp"])


def test_read_legacy_grouping():
    df = pcapml.read_pcapml(LEGACY)
    assert len(df) == 151
    # Legacy positional comments: every packet has a sample id and a label.
    assert df["sample_id"].notna().all()
    assert df["label"].notna().all()
    # This fixture holds several OS-labeled samples.
    assert df["label"].nunique() > 1
    # Ethernet frames decode to IP addresses too.
    assert df["src_ip"].notna().any()

    # Sample grouping: each Sample is internally consistent in id and label.
    grouped = list(pcapml.samples(LEGACY))
    assert len(grouped) >= 1
    assert sum(len(s) for s in grouped) == 151
    for s in grouped:
        assert (s.df["sample_id"] == s.sample_id).all()


def test_samples_iterator():
    samples = list(pcapml.samples(KEYED))
    assert len(samples) == 1
    s = samples[0]
    assert s.sample_id == "0"
    assert s.sid == "0"            # README-compatible alias
    assert s.label == "curl"
    assert len(s) == 9
    assert len(s.packets) == 9    # README-compatible alias
    assert s.metadata["dst"] == "example.com"


def test_include_raw_false_drops_column():
    df = pcapml.read_pcapml(KEYED, include_raw=False)
    assert "raw" not in df.columns
    assert "raw" in pcapml.read_pcapml(KEYED).columns


def _write_pcapng(path, comments, link_type=101):
    """Write a minimal pcapng with one IPv4/TCP packet per comment."""
    import struct

    def block(btype, body):
        blen = 12 + len(body)
        return struct.pack("<II", btype, blen) + body + struct.pack("<I", blen)

    pad = lambda n: (4 - n % 4) % 4
    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack("<HHI", link_type, 0, 0))
    ip = bytes([0x45, 0, 0, 40]) + b"\x00" * 5 + bytes([6]) + b"\x00\x00" + \
        bytes([192, 168, 0, 1]) + bytes([1, 1, 1, 1])
    data = ip + struct.pack("!HH", 1234, 80) + b"\x00" * 12
    for comment in comments:
        cb = comment.encode()
        opts = struct.pack("<HH", 1, len(cb)) + cb + b"\x00" * pad(len(cb)) + \
            struct.pack("<HH", 0, 0)
        body = struct.pack("<IIIII", 0, 0, 0, len(data), len(data)) + \
            data + b"\x00" * pad(len(data)) + opts
        out += block(6, body)
    with open(path, "wb") as f:
        f.write(out)


def test_arbitrary_keys_promoted_to_columns(tmp_path):
    p = tmp_path / "extra.pcapng"
    _write_pcapng(p, [
        "s=7,proc=curl,dst=youtube.com,asn=15169,foo=bar",
        "s=7,proc=curl,dst=youtube.com,asn=15169",  # no foo -> sparse
    ])
    df = pcapml.read_pcapml(str(p))
    # Core schema preserved, unknown keys appended as their own columns.
    assert list(df.columns)[: len(pcapml.COLUMNS)] == pcapml.COLUMNS
    assert "asn" in df.columns and "foo" in df.columns
    assert df["asn"].tolist() == ["15169", "15169"]
    assert df["foo"][0] == "bar"
    assert pd.isna(df["foo"][1])  # missing key -> <NA>
    assert df["asn"].dtype == "string"


def test_arbitrary_key_collision_is_prefixed(tmp_path):
    p = tmp_path / "clash.pcapng"
    _write_pcapng(p, ["s=1,proc=x,length=999"])  # "length" clashes with core column
    df = pcapml.read_pcapml(str(p))
    assert "meta_length" in df.columns
    assert df["meta_length"][0] == "999"
    assert df["length"][0] == 36  # core column untouched (real wire length)


def test_dtypes_nullable_ports():
    df = pcapml.read_pcapml(KEYED)
    assert df["src_port"].dtype == "Int64"
    assert df["dst_port"].dtype == "Int64"
    assert df["sample_id"].dtype == "string"
