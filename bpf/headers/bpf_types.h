// SPDX-License-Identifier: GPL-2.0-only
// Minimal type definitions for BPF programs that don't need CO-RE/BTF.
// Replaces vmlinux.h when kernel BTF is unavailable.

#ifndef __BPF_TYPES_H
#define __BPF_TYPES_H

typedef unsigned char       __u8;
typedef unsigned short      __u16;
typedef unsigned int        __u32;
typedef unsigned long long  __u64;
typedef signed char         __s8;
typedef signed short        __s16;
typedef signed int          __s32;
typedef signed long long    __s64;

// Network byte-order types used by bpf_helper_defs.h
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
typedef __u32 __sum16;

// BPF map update flags
#define BPF_ANY 0

// BPF map types
enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC        = 0,
    BPF_MAP_TYPE_HASH          = 1,
    BPF_MAP_TYPE_ARRAY         = 2,
    BPF_MAP_TYPE_PROG_ARRAY    = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_HASH   = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY  = 6,
    BPF_MAP_TYPE_STACK_TRACE   = 7,
    BPF_MAP_TYPE_CGROUP_ARRAY  = 8,
    BPF_MAP_TYPE_LRU_HASH      = 9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
    BPF_MAP_TYPE_LPM_TRIE      = 11,
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
    BPF_MAP_TYPE_HASH_OF_MAPS  = 13,
    BPF_MAP_TYPE_DEVMAP        = 14,
    BPF_MAP_TYPE_SOCKMAP        = 15,
    BPF_MAP_TYPE_CPUMAP        = 16,
    BPF_MAP_TYPE_XSKMAP        = 17,
    BPF_MAP_TYPE_SOCKHASH      = 18,
    BPF_MAP_TYPE_CGROUP_STORAGE = 19,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
    BPF_MAP_TYPE_QUEUE         = 22,
    BPF_MAP_TYPE_STACK         = 23,
    BPF_MAP_TYPE_SK_STORAGE    = 24,
    BPF_MAP_TYPE_DEVMAP_HASH   = 25,
    BPF_MAP_TYPE_STRUCT_OPS    = 26,
    BPF_MAP_TYPE_RINGBUF       = 27,
    BPF_MAP_TYPE_INODE_STORAGE = 28,
    BPF_MAP_TYPE_TASK_STORAGE  = 29,
};

// Stable BPF context for TC programs (not a kernel struct — ABI-stable)
struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
    __u32 napi_id;
    __u32 family;
    __u32 remote_ip4;
    __u32 local_ip4;
    __u32 remote_ip6[4];
    __u32 local_ip6[4];
    __u32 remote_port;
    __u32 local_port;
    __u32 data_meta;
    __u64 tstamp;
    __u32 wire_len;
    __u32 gso_segs;
    __u64 sk;
    __u32 gso_size;
};

#endif
