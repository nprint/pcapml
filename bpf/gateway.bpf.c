// SPDX-License-Identifier: GPL-2.0-only
// pcapml gateway: eBPF TC programs for network-path packet capture
// (no process attribution, used on routers/middleboxes)

// No vmlinux.h — gateway BPF uses only stable BPF context structs,
// no CO-RE or kernel BTF required.
#include "bpf_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_PKT_LEN  1500
#define ETH_HLEN     14

// Reuse the same event layout as host mode so userspace parsing is shared.
// In gateway mode: pid=0, uid=0, comm=zeros.
struct pkt_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u32 pkt_len;
    __u32 cap_len;
    __u8  direction; // 0 = wan2lan, 1 = lan2wan
    __u8  pad[3];
    char  comm[16];
    __u8  pkt_data[MAX_PKT_LEN];
};

// Config map keys
#define CFG_SNAP_LEN    0
#define CFG_INCLUDE_DNS 1

#define DNS_PORT 53

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} gw_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4);
} gw_config SEC(".maps");


static __always_inline int capture_tc(struct __sk_buff *skb, __u8 direction) {
    // TC context includes L2 header; skip to IP
    __u32 l2_len = ETH_HLEN;
    __u32 pkt_len = skb->len;

    if (pkt_len <= l2_len)
        return 1; // TC_ACT_OK — too small, pass through

    __u32 ip_len = pkt_len - l2_len;
    // verifier now knows ip_len >= 1 (pkt_len > l2_len established above)

    // Check for IPv4 (EtherType at offset 12)
    __u16 eth_proto;
    if (bpf_skb_load_bytes(skb, 12, &eth_proto, 2) < 0)
        return 1;
    if (bpf_ntohs(eth_proto) != 0x0800) // ETH_P_IP
        return 1;

    // Parse IP header minimally for DNS filtering
    __u8 ip_ver_ihl;
    if (bpf_skb_load_bytes(skb, l2_len, &ip_ver_ihl, 1) < 0)
        return 1;
    if ((ip_ver_ihl >> 4) != 4)
        return 1;

    __u32 ihl = (ip_ver_ihl & 0x0F) * 4;
    if (ihl < 20 || pkt_len < l2_len + ihl + 4)
        return 1;

    // Read protocol
    __u8 proto;
    if (bpf_skb_load_bytes(skb, l2_len + 9, &proto, 1) < 0)
        return 1;

    // Filter DNS unless configured to include
    if (proto == 17 || proto == 6) { // UDP or TCP
        __u16 ports[2];
        if (bpf_skb_load_bytes(skb, l2_len + ihl, ports, 4) == 0) {
            __u16 sport = bpf_ntohs(ports[0]);
            __u16 dport = bpf_ntohs(ports[1]);
            if (sport == DNS_PORT || dport == DNS_PORT) {
                __u32 dns_key = CFG_INCLUDE_DNS;
                __u32 *dns_val = bpf_map_lookup_elem(&gw_config, &dns_key);
                if (!dns_val || !*dns_val)
                    return 1;
            }
        }
    }

    // Capture length — must pass BPF verifier as R4 in [1, MAX_PKT_LEN].
    //
    // Problem: clang emits <<32;>>32 zero-extension shifts on u32 arithmetic
    // results before passing them to BPF helpers.  The kernel 6.6 verifier
    // loses the lower bound through these shifts (ip_len's >= 1 becomes >= 0).
    //
    // Fix: subtraction-wrap trick.  Subtract 1, barrier to prevent algebra
    // folding, then JLT-clamp against an immediate.  On the fall-through
    // path the verifier knows copy_m1 in [0, MAX_PKT_LEN-1] via JLT
    // narrowing (which DOES work on kernel 6.6).  Adding 1 back gives
    // copy_len in [1, MAX_PKT_LEN] via ALU range tracking.
    //
    // Snap-length truncation is handled in userspace (Go).
    __u32 copy_m1 = ip_len - 1u;
    asm volatile("" : "+r"(copy_m1));   // prevent clang from folding -1/+1
    if (copy_m1 >= MAX_PKT_LEN)         // JGE imm → fall-through: [0, MAX_PKT_LEN-1]
        copy_m1 = MAX_PKT_LEN - 1u;
    __u32 copy_len = copy_m1 + 1u;      // ALU +1: [1, MAX_PKT_LEN]

    struct pkt_event *evt = bpf_ringbuf_reserve(&gw_events,
                                                  sizeof(struct pkt_event), 0);
    if (!evt)
        return 1;

    evt->timestamp_ns = bpf_ktime_get_boot_ns();
    evt->pid = 0;
    evt->uid = 0;
    evt->pkt_len = ip_len;
    evt->cap_len = copy_len;
    evt->direction = direction;
    __builtin_memset(evt->comm, 0, 16);

    if (bpf_skb_load_bytes(skb, l2_len, evt->pkt_data, copy_len) < 0) {
        bpf_ringbuf_discard(evt, 0);
        return 1;
    }

    bpf_ringbuf_submit(evt, 0);
    return 1; // TC_ACT_OK — always pass through
}

// On WAN interface: ingress = packets arriving from internet = wan2lan
SEC("tc/wan_ingress")
int tc_wan_ingress(struct __sk_buff *skb) {
    return capture_tc(skb, 0); // wan2lan
}

// On WAN interface: egress = packets leaving to internet = lan2wan
SEC("tc/wan_egress")
int tc_wan_egress(struct __sk_buff *skb) {
    return capture_tc(skb, 1); // lan2wan
}

char _license[] SEC("license") = "Dual BSD/GPL";
