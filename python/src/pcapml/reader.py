# SPDX-License-Identifier: Apache-2.0
"""High-level pcapml reader: pcapng -> pandas DataFrame and per-sample grouping."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Tuple, Union

import pandas as pd

from . import _decode
from ._pcapng import Packet, iter_packets

# Column order for the per-packet DataFrame.
COLUMNS = [
    "timestamp",
    "sample_id",
    "label",
    "direction",
    "dst",
    "src_ip",
    "dst_ip",
    "proto",
    "src_port",
    "dst_port",
    "length",
    "raw",
]

# Comment keys already surfaced as dedicated core columns. Any *other* key found
# in a comment is promoted to its own column, named after the key.
_CORE_KEYS = frozenset({"s", "proc", "label", "dir", "d", "dst"})


def parse_comment(comment: str) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], Dict[str, str]]:
    """Parse a pcapml EPB comment into (sample_id, label, direction, dst, metadata).

    Handles both the keyed form (``s=0,proc=curl,dir=lan2wan,dst=example.com``)
    and the legacy positional form (``<sample_id>,<label>``). ``metadata`` holds
    every ``key=value`` pair found, verbatim.
    """
    meta: Dict[str, str] = {}
    positional: List[str] = []
    if comment:
        for field in comment.split(","):
            key, sep, value = field.partition("=")
            if sep:
                meta[key] = value
            else:
                positional.append(field)

    sample_id = meta.get("s")
    if sample_id is None and positional:
        sample_id = positional[0]

    label = meta.get("proc") or meta.get("label")
    if label is None and len(positional) > 1:
        label = positional[1]

    direction = meta.get("dir") or meta.get("d")
    dst = meta.get("dst")

    return sample_id, label, direction, dst, meta


def _row(pkt: Packet) -> dict:
    sample_id, label, direction, dst, meta = parse_comment(pkt.comment)
    decoded = _decode.decode(pkt.data, pkt.link_type)
    row = {
        "timestamp": pkt.ts_nanos,
        "sample_id": sample_id,
        "label": label,
        "direction": direction,
        "dst": dst,
        "src_ip": decoded["src_ip"],
        "dst_ip": decoded["dst_ip"],
        "proto": decoded["proto"],
        "src_port": decoded["src_port"],
        "dst_port": decoded["dst_port"],
        "length": pkt.orig_len,
        "raw": pkt.data,
    }
    # Promote any non-core comment key to its own column. If a key would clash
    # with a built-in column, prefix it with "meta_" rather than clobbering.
    for key, value in meta.items():
        if key in _CORE_KEYS:
            continue
        col = key if key not in row else "meta_" + key
        row[col] = value
    return row


def _finalize(df: pd.DataFrame) -> pd.DataFrame:
    """Apply consistent dtypes to a freshly built packet DataFrame.

    Core columns get fixed dtypes and a stable order; any extra columns
    (promoted from arbitrary comment keys) follow, typed as strings.
    """
    if df.empty:
        df = pd.DataFrame({c: pd.Series(dtype="object") for c in COLUMNS})
    for col in COLUMNS:
        if col not in df.columns:
            df[col] = pd.NA
    extra_cols = [c for c in df.columns if c not in COLUMNS]
    df = df[COLUMNS + extra_cols]

    df["timestamp"] = pd.to_datetime(df["timestamp"], unit="ns", utc=True)
    for col in ("sample_id", "label", "direction", "dst", "src_ip", "dst_ip", "proto"):
        df[col] = df[col].astype("string")
    for col in ("src_port", "dst_port", "length"):
        df[col] = df[col].astype("Int64")
    for col in extra_cols:
        df[col] = df[col].astype("string")
    return df


def read_pcapml(source: Union[str], include_raw: bool = True) -> pd.DataFrame:
    """Read a pcapml-labeled pcapng file into a pandas DataFrame, one row per packet.

    Parameters
    ----------
    source:
        Path to a ``.pcapng`` file produced by pcapml.
    include_raw:
        Keep the full packet bytes in the ``raw`` column (default ``True``).
        Set ``False`` to drop it and save memory.
    """
    df = _finalize(pd.DataFrame([_row(p) for p in iter_packets(source)]))
    if not include_raw:
        df = df.drop(columns=["raw"])
    return df


# Backwards/ergonomic alias.
read = read_pcapml


@dataclass
class Sample:
    """All packets that share one sample ID, plus that sample's metadata."""

    sample_id: Optional[str]
    label: Optional[str]
    metadata: Dict[str, str]
    df: pd.DataFrame

    # Aliases matching the README's sampler() examples.
    @property
    def sid(self) -> Optional[str]:
        return self.sample_id

    @property
    def packets(self) -> pd.DataFrame:
        return self.df

    def __len__(self) -> int:
        return len(self.df)


def samples(source: Union[str]) -> Iterator[Sample]:
    """Iterate over samples, grouping consecutive packets by sample ID.

    pcapml writes (and its ``sort`` subcommand guarantees) that packets of a
    sample are contiguous, so grouping is streaming and order-preserving.
    """
    current_id: Optional[str] = None
    rows: List[dict] = []
    meta: Dict[str, str] = {}
    label: Optional[str] = None
    have_group = False

    for pkt in iter_packets(source):
        sample_id, lbl, _direction, _dst, pkt_meta = parse_comment(pkt.comment)
        if not have_group:
            current_id, label, meta, have_group = sample_id, lbl, pkt_meta, True
        elif sample_id != current_id:
            yield Sample(current_id, label, meta, _finalize(pd.DataFrame(rows)))
            rows = []
            current_id, label, meta = sample_id, lbl, pkt_meta
        rows.append(_row(pkt))

    if have_group:
        yield Sample(current_id, label, meta, _finalize(pd.DataFrame(rows)))


# README-compatible alias.
sampler = samples
