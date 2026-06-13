# SPDX-License-Identifier: Apache-2.0
"""pcapml: read pcapml-labeled network traces into pandas DataFrames.

Quick start
-----------
>>> import pcapml
>>> df = pcapml.read_pcapml("dataset.pcapng")
>>> df[["timestamp", "sample_id", "label", "src_ip", "dst_ip", "proto"]].head()

Group by sample:
>>> for sample in pcapml.samples("dataset.pcapng"):
...     print(sample.sample_id, sample.label, len(sample))
"""

from importlib.metadata import PackageNotFoundError, version

from ._pcapng import Interface, Packet, iter_packets
from .reader import (
    COLUMNS,
    Sample,
    parse_comment,
    read,
    read_pcapml,
    sampler,
    samples,
)

try:
    # Single source of truth: the version declared in pyproject.toml.
    __version__ = version("pcapml")
except PackageNotFoundError:  # running from a source tree that isn't installed
    __version__ = "0.0.0+unknown"

__all__ = [
    "read_pcapml",
    "read",
    "samples",
    "sampler",
    "Sample",
    "parse_comment",
    "iter_packets",
    "Packet",
    "Interface",
    "COLUMNS",
    "__version__",
]
