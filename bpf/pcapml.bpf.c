// SPDX-License-Identifier: GPL-2.0-only
// pcapml: eBPF programs for process-aware packet capture

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#define MAX_COMM_LEN 16
#define MAX_PKT_LEN  1500
#define DIRECTION_INGRESS 0
#define DIRECTION_EGRESS  1

// Config map keys
#define CFG_SNAP_LEN    0
#define CFG_USE_ALLOW   1
#define CFG_USE_DENY    2
#define CFG_INCLUDE_DNS 3
#define CFG_CGROUP_INFO 4

#define DNS_PORT 53

// 5-tuple flow key (IPv4 only for MVP)
struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  pad[3];
};

// Process info stored per flow
struct process_info {
    __u32 pid;
    __u32 uid;
    __u64 cgroup_id;
    char  comm[MAX_COMM_LEN];
};

// Packet event sent to userspace via ring buffer
struct pkt_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u32 pkt_len;
    __u32 cap_len;
    __u8  direction;
    __u8  pad[3];
    char  comm[MAX_COMM_LEN];
    __u32 pad2;
    __u64 cgroup_id;
    __u8  pkt_data[MAX_PKT_LEN];
};

// --- Maps ---

// 5-tuple -> process info
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct process_info);
    __uint(max_entries, 65536);
} flow_map SEC(".maps");

// Ring buffer for packet events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024); // 16 MB
} events SEC(".maps");

// Allow list: comm -> 1 (if present, only capture these)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[MAX_COMM_LEN]);
    __type(value, __u8);
    __uint(max_entries, 256);
} comm_allow SEC(".maps");

// Deny list: comm -> 1 (if present, skip these)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[MAX_COMM_LEN]);
    __type(value, __u8);
    __uint(max_entries, 256);
} comm_deny SEC(".maps");

// Configuration values
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 8);
} pcapml_config SEC(".maps");

// Per-CPU scratch space to launder cap_len through a map read, giving the
// BPF verifier a fresh scalar it can bound-check without prior history.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} scratch SEC(".maps");

// --- Helpers ---

static __always_inline void record_flow(struct sock *sk) {
    struct flow_key key = {};

    key.proto = BPF_CORE_READ(sk, sk_protocol);
    key.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    if (key.saddr == 0 && key.daddr == 0)
        return;

    struct process_info info = {};
    info.pid = bpf_get_current_pid_tgid() >> 32;
    info.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    __u32 cg_key = CFG_CGROUP_INFO;
    __u32 *cg_val = bpf_map_lookup_elem(&pcapml_config, &cg_key);
    if (cg_val && *cg_val)
        info.cgroup_id = bpf_get_current_cgroup_id();

    bpf_map_update_elem(&flow_map, &key, &info, BPF_ANY);
}

static __always_inline void delete_flow(struct sock *sk) {
    struct flow_key key = {};

    key.proto = BPF_CORE_READ(sk, sk_protocol);
    key.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_map_delete_elem(&flow_map, &key);
}

// Parse IPv4 5-tuple from an skb (cgroup_skb context, L3 data)
static __always_inline int parse_ipv4_5tuple(struct __sk_buff *skb,
                                              struct flow_key *key) {
    __u8 ip_ver_ihl;
    if (bpf_skb_load_bytes(skb, 0, &ip_ver_ihl, 1) < 0)
        return -1;

    __u8 ip_version = ip_ver_ihl >> 4;
    if (ip_version != 4)
        return -1; // IPv6 not yet supported

    __u32 iph_len = (ip_ver_ihl & 0x0F) * 4;
    if (iph_len < 20)
        return -1;

    // Read src/dst addr and protocol from IP header
    // offsets: protocol=9, saddr=12, daddr=16
    __u8 proto;
    if (bpf_skb_load_bytes(skb, 9, &proto, 1) < 0)
        return -1;
    key->proto = proto;

    if (bpf_skb_load_bytes(skb, 12, &key->saddr, 4) < 0)
        return -1;
    if (bpf_skb_load_bytes(skb, 16, &key->daddr, 4) < 0)
        return -1;

    // Read ports from TCP or UDP header
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        __u16 ports[2]; // [src, dst] in network byte order
        if (bpf_skb_load_bytes(skb, iph_len, ports, 4) < 0)
            return -1;
        key->sport = bpf_ntohs(ports[0]);
        key->dport = bpf_ntohs(ports[1]);
    } else {
        return -1; // only TCP/UDP for now
    }

    return 0;
}

// Check allow/deny lists. Returns 1 if packet should be captured, 0 if not.
static __always_inline int check_comm_filter(char *comm) {
    __u32 key;
    __u32 *val;

    key = CFG_USE_ALLOW;
    val = bpf_map_lookup_elem(&pcapml_config, &key);
    if (val && *val) {
        if (!bpf_map_lookup_elem(&comm_allow, comm))
            return 0; // not in allow list
    }

    key = CFG_USE_DENY;
    val = bpf_map_lookup_elem(&pcapml_config, &key);
    if (val && *val) {
        if (bpf_map_lookup_elem(&comm_deny, comm))
            return 0; // in deny list
    }

    return 1;
}

static __always_inline int capture_packet(struct __sk_buff *skb,
                                           __u8 direction) {
    struct flow_key key = {};
    if (parse_ipv4_5tuple(skb, &key) < 0)
        return 1; // allow but don't capture

    // Filter DNS traffic (port 53) unless --include-dns is set
    if (key.sport == DNS_PORT || key.dport == DNS_PORT) {
        __u32 dns_key = CFG_INCLUDE_DNS;
        __u32 *dns_val = bpf_map_lookup_elem(&pcapml_config, &dns_key);
        if (!dns_val || !*dns_val)
            return 1; // drop DNS by default
    }

    // Look up process info by 5-tuple
    struct process_info *info = bpf_map_lookup_elem(&flow_map, &key);
    if (!info) {
        // Try reversed 5-tuple (for ingress on outbound connections,
        // or egress on inbound connections)
        struct flow_key rkey = {
            .saddr = key.daddr,
            .daddr = key.saddr,
            .sport = key.dport,
            .dport = key.sport,
            .proto = key.proto,
        };
        info = bpf_map_lookup_elem(&flow_map, &rkey);
    }
    if (!info)
        return 1; // unknown socket, skip

    // Apply allow/deny filters
    if (!check_comm_filter(info->comm))
        return 1;

    // Determine capture length
    __u32 snap_len = MAX_PKT_LEN;
    __u32 cfg_key = CFG_SNAP_LEN;
    __u32 *cfg_val = bpf_map_lookup_elem(&pcapml_config, &cfg_key);
    if (cfg_val && *cfg_val > 0 && *cfg_val < MAX_PKT_LEN)
        snap_len = *cfg_val;

    __u32 pkt_len = skb->len;
    __u32 cap_len = pkt_len;
    if (cap_len > snap_len)
        cap_len = snap_len;
    if (cap_len > MAX_PKT_LEN)
        cap_len = MAX_PKT_LEN;
    if (cap_len == 0)
        return 1;

    // Launder cap_len through a per-CPU map so the verifier gets a fresh
    // scalar with no prior range history.
    __u32 scratch_key = 0;
    bpf_map_update_elem(&scratch, &scratch_key, &cap_len, BPF_ANY);

    // Reserve ring buffer space and build event
    struct pkt_event *evt = bpf_ringbuf_reserve(&events,
                                                 sizeof(struct pkt_event), 0);
    if (!evt)
        return 1; // ring buffer full, drop

    evt->timestamp_ns = bpf_ktime_get_boot_ns();
    evt->pid = info->pid;
    evt->uid = info->uid;
    evt->pkt_len = pkt_len;
    evt->direction = direction;
    __builtin_memcpy(evt->comm, info->comm, MAX_COMM_LEN);
    evt->cgroup_id = info->cgroup_id;

    // Read cap_len back from the map — verifier sees an unbounded scalar.
    // Read into a local ONCE, then check the local.
    __u32 *len_ptr = bpf_map_lookup_elem(&scratch, &scratch_key);
    if (!len_ptr) {
        bpf_ringbuf_discard(evt, 0);
        return 1;
    }
    __u32 read_len = *len_ptr;
    __u32 min_len = 1;
    asm volatile("" : "+r"(min_len));
    if (read_len < min_len || read_len > MAX_PKT_LEN) {
        bpf_ringbuf_discard(evt, 0);
        return 1;
    }
    evt->cap_len = read_len;

    // Copy packet data
    if (bpf_skb_load_bytes(skb, 0, evt->pkt_data, read_len) < 0) {
        bpf_ringbuf_discard(evt, 0);
        return 1;
    }

    bpf_ringbuf_submit(evt, 0);
    return 1; // always allow packet through
}

// --- Socket lifecycle probes ---

SEC("kprobe/tcp_connect")
int BPF_KPROBE(kp_tcp_connect, struct sock *sk) {
    record_flow(sk);
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(kp_inet_csk_accept_ret, struct sock *sk) {
    if (!sk)
        return 0;
    record_flow(sk);
    return 0;
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(kp_tcp_close, struct sock *sk) {
    delete_flow(sk);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kp_udp_sendmsg, struct sock *sk) {
    // Only record if we have a valid destination (connected socket)
    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    if (daddr == 0)
        return 0;

    record_flow(sk);
    return 0;
}

SEC("kprobe/udp_destroy_sock")
int BPF_KPROBE(kp_udp_destroy_sock, struct sock *sk) {
    delete_flow(sk);
    return 0;
}

// --- Packet capture via cgroup_skb ---

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *skb) {
    return capture_packet(skb, DIRECTION_EGRESS);
}

SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *skb) {
    return capture_packet(skb, DIRECTION_INGRESS);
}

char _license[] SEC("license") = "Dual BSD/GPL";
