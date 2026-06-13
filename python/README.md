# pcapml (Python)

Read [pcapml](https://github.com/nprint/pcapml)-labeled network traces into
[pandas](https://pandas.pydata.org/) DataFrames. **Pure Python** — no native
extensions, no libpcap, no Go binary required. The only dependency is pandas.

pcapml stores ground-truth labels as per-packet comments inside standard
pcapng files. This package parses those files directly so you can go from a
labeled capture to a tidy DataFrame in one line.

## Install

```bash
pip install pcapml
```

Or from this repository:

```bash
pip install ./python
```

## Quick start

```python
import pcapml

df = pcapml.read_pcapml("dataset.pcapng")
print(df.head())
```

```
                          timestamp sample_id label direction         dst        src_ip        dst_ip proto  src_port  dst_port  length
2026-03-19 22:25:24.189764096+00:00         0  curl   lan2wan example.com 192.168.1.188 104.18.26.120   TCP     47954        80      60
2026-03-19 22:25:24.195076864+00:00         0  curl   wan2lan example.com 104.18.26.120 192.168.1.188   TCP        80     47954      60
...
```

### Columns

| Column | Dtype | Description |
|--------|-------|-------------|
| `timestamp` | `datetime64[ns, UTC]` | Packet capture time |
| `sample_id` | `string` | pcapml sample ID (kept as string — IDs can exceed 2⁶⁴) |
| `label` | `string` | Sample label / process name |
| `direction` | `string` | Direction tag if present (`lan2wan`, `wan2lan`, `e`, `i`, …) |
| `dst` | `string` | Resolved destination domain, if any |
| `src_ip`, `dst_ip` | `string` | L3 addresses (IPv4 or IPv6) |
| `proto` | `string` | `TCP`, `UDP`, `ICMP`, … (or the numeric value) |
| `src_port`, `dst_port` | `Int64` | L4 ports (nullable) |
| `length` | `Int64` | Original on-wire packet length |
| `raw` | `bytes` | Full captured packet bytes |

**Arbitrary comment keys** are promoted automatically. The columns above are the
fixed core schema; any other `key=value` pair in a comment becomes its own
column named after the key (sparse keys fill with `<NA>`). For example a comment
`s=0,proc=curl,dst=youtube.com,asn=15169` yields an extra `asn` column. If a key
collides with a core column name it is prefixed (`meta_<key>`) instead of
overwriting it.

Pass `include_raw=False` to drop the `raw` column and save memory:

```python
df = pcapml.read_pcapml("dataset.pcapng", include_raw=False)
```

The header decoding (IPv4/IPv6 + TCP/UDP) is intentionally lightweight. The
`raw` bytes are always available if you want a full dissector such as
[dpkt](https://github.com/kbandla/dpkt) or [scapy](https://scapy.net/):

```python
import dpkt
df["eth"] = df["raw"].apply(dpkt.ethernet.Ethernet)  # for Ethernet linktype
```

## Iterating by sample

For ML workflows it's often handier to work one sample at a time. `samples()`
groups consecutive packets by sample ID (pcapml writes each sample's packets
contiguously; use `pcapml sort` first if yours aren't):

```python
for sample in pcapml.samples("dataset.pcapng"):
    print(sample.sample_id, sample.label, len(sample))
    sample.df          # a DataFrame of just this sample's packets
    sample.metadata    # dict of every key=value pair from the comment
```

`Sample` also exposes `.sid` and `.packets` aliases.

## Label formats

Both pcapml comment encodings are supported transparently:

- **Keyed** (eBPF / gateway capture): `s=0,proc=curl,dir=lan2wan,dst=example.com`
- **Legacy positional**: `18205618432581910911,windows-10`

## Lower-level access

If you don't want pandas in the loop, iterate raw packets directly:

```python
from pcapml import iter_packets, parse_comment

for pkt in iter_packets("dataset.pcapng"):
    sid, label, direction, dst, meta = parse_comment(pkt.comment)
    pkt.timestamp   # POSIX seconds (float)
    pkt.data        # raw bytes
    pkt.link_type   # pcapng linktype (1 = Ethernet, 101 = RAW IPv4)
```

## License

Apache-2.0.
