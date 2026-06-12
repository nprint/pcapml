# pcapml

A unified CLI tool for creating and manipulating ground-truth labeled network
traffic datasets. It supports both offline operations (label, split, sort,
strip) and eBPF-based live capture that automatically labels every packet with
the process that sent or received it.

## Installation

### Build requirements

- Go 1.22+
- libpcap-dev (for the `label` subcommand)
- clang, libbpf-dev, bpftool, llvm-strip (for the `capture` subcommand)

On Debian/Ubuntu:

```bash
sudo apt install libpcap-dev clang libbpf-dev linux-tools-common llvm
```

### Build

```bash
make
```

This generates the kernel BTF header (`vmlinux.h`), compiles the eBPF C
programs, generates Go bindings, and builds the `pcapml` binary.

## Usage

```
pcapml <subcommand> [flags]
```

### capture — eBPF live capture

Captures network traffic and labels every packet with the process/application
that owns the socket. Uses eBPF kprobes and cgroup_skb programs. Requires root.

```bash
sudo ./pcapml capture -o dataset.pcapng
sudo ./pcapml capture -o dataset.pcapng --allow firefox,chrome
sudo ./pcapml capture -o dataset.pcapng --deny sshd,snapd
sudo ./pcapml capture -o dataset.pcapng --include-dns
sudo ./pcapml capture -o dataset.pcapng --no-resolve
```

By default, DNS responses and TLS ClientHello SNI are parsed to resolve
destination IPs to domain names (e.g. `dst=youtube.com`). DNS packets are
consumed for resolution but not written to the output file unless
`--include-dns` is set.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-o` | `capture.pcapng` | Output pcapng file |
| `--allow` | | Comma-separated allow list of process names |
| `--deny` | | Comma-separated deny list of process names |
| `--snap-len` | `1500` | Max bytes to capture per packet |
| `--cgroup` | `/sys/fs/cgroup` | Cgroup v2 path to attach to |
| `--include-dns` | `false` | Include DNS (port 53) traffic in output |
| `--no-resolve` | `false` | Disable DNS/SNI domain resolution in labels |

**Requirements:** Linux 5.8+ with BTF, cgroup v2, root or CAP_BPF +
CAP_NET_ADMIN + CAP_PERFMON.

**Output format:** pcapng with `LINKTYPE_RAW` (101). Each packet has a comment
option in the format `sample_id,process_name,d=e|i[,dst=domain]`.

### label — apply labels to a pcap file

Labels packets in a pcap file using BPF filters and timestamp ranges defined
in a label file.

```bash
./pcapml label -i traffic.pcap -l labels.csv -o labeled.pcapng
./pcapml label -i traffic.pcap -l labels.csv -o labeled.pcapng -stats
```

**Label file format** (CSV, one rule per line):

```
BPF:<filter>[|TS_START:<epoch>][|TS_END:<epoch>],<label>[,<hash_key>]
```

Examples:

```
BPF:host 192.168.1.10,web-server
BPF:tcp port 443|TS_START:1700000000|TS_END:1700003600,https-traffic
BPF:host 10.0.0.5,client-a,group1
BPF:host 10.0.0.6,client-b,group1
```

Lines starting with `#` are comments. The optional `hash_key` field groups
multiple rules under the same sample ID (useful when multiple BPF filters
should be treated as one sample).

**Flags:**

| Flag | Description |
|------|-------------|
| `-i` | Input pcap file |
| `-o` | Output pcapng file |
| `-l` | Label file (CSV) |
| `-stats` | Print labeling statistics |

### sort — sort by sample ID

Sorts packets in a labeled pcapng file by sample ID (primary) then timestamp
(secondary). Required before `split` if packets aren't already grouped.

```bash
./pcapml sort -i labeled.pcapng -o sorted.pcapng
```

### split — split into per-sample pcap files

Splits a labeled (and sorted) pcapng into individual pcap files, one per
sample. Produces a `metadata.csv` mapping filenames to labels.

```bash
./pcapml split -i sorted.pcapng -o samples/
cat samples/metadata.csv
```

### strip — remove labels

Removes all pcapml labels from a pcapng file and converts to plain pcap.

```bash
./pcapml strip -i labeled.pcapng -o plain.pcap
```

### compare — evaluate labeling accuracy

Compares a ground-truth labeled pcapng (e.g. from eBPF capture) against a
post-hoc labeled pcapng (e.g. from the `label` subcommand). Prints per-label
precision, recall, and a confusion matrix.

```bash
./pcapml compare -truth ground_truth.pcapng -test relabeled.pcapng
./pcapml compare -truth ground_truth.pcapng -test relabeled.pcapng -csv confusion.csv
```

## Typical workflows

### Live capture (ground truth from eBPF)

```bash
# Capture labeled traffic
sudo ./pcapml capture -o dataset.pcapng

# Split into per-application pcap files
./pcapml sort -i dataset.pcapng -o sorted.pcapng
./pcapml split -i sorted.pcapng -o samples/
```

### Offline labeling (BPF filters)

```bash
# Label a pcap with BPF rules
./pcapml label -i traffic.pcap -l labels.csv -o labeled.pcapng

# Sort and split
./pcapml sort -i labeled.pcapng -o sorted.pcapng
./pcapml split -i sorted.pcapng -o samples/
```

### Read samples in Python

```bash
pip install ../python   # or: pip install pcapml
```

```python
import pcapml

for sample in pcapml.sampler("sorted.pcapng"):
    print(sample.sid, sample.metadata, len(sample.packets))
```

## pcapng label format

Labels are stored as EPB (Enhanced Packet Block) comment options in standard
pcapng format. The comment string is comma-separated:

```
sample_id,label[,key=value...]
```

For live capture: `42,chrome,d=e,dst=youtube.com`

For offline labeling: `42,web-server`

This format is readable by Wireshark, tcpdump, and any pcapng-aware tool.

## Architecture (live capture)

The `capture` subcommand uses eBPF to correlate packets with processes:

1. **kprobes** on socket lifecycle functions (`tcp_connect`, `inet_csk_accept`,
   `tcp_close`, `udp_sendmsg`, `udp_destroy_sock`) extract 5-tuples from
   `struct sock` and store `{pid, comm, uid}` in a hash map.

2. **cgroup_skb** programs on the root cgroup capture all packets, look up the
   5-tuple in the flow map, filter DNS by default, and push matched packets
   to a ring buffer.

3. **Userspace** reads the ring buffer, assigns sample IDs per flow (normalized
   5-tuple), resolves destination domains via DNS/SNI, and writes pcapng with
   labels.

## License

This project uses a dual-license model:

- **Apache-2.0** — all userspace Go code, libraries, and CLI tools (`LICENSE`)
- **GPL-2.0-only** — eBPF programs loaded into the Linux kernel and generated Go
  bindings that embed GPL bytecode (`LICENSE-GPL`)

Each file has an `SPDX-License-Identifier` header indicating which license
applies. In summary:

| Path | License |
|------|---------|
| `bpf/*.bpf.c`, `bpf/headers/bpf_types.h` | GPL-2.0-only |
| `cmd/*_bpf*.go` (generated by bpf2go) | GPL-2.0-only |
| Everything else | Apache-2.0 |

The eBPF programs must be GPL-2.0 because they run inside the Linux kernel and
use GPL-only BPF helpers. The userspace code is Apache-2.0 to allow the widest
possible reuse of the pcapng library, CLI tools, and analysis commands.

## Current limitations

- IPv4 only (live capture)
- No L2 headers in live capture (cgroup_skb provides L3 raw IP)
- Connected UDP only (unconnected `sendto()` not tracked)
- x86_64 only (arm64 is a one-line change in `gen.go`)
- No file rotation
