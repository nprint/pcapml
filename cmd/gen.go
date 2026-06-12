// SPDX-License-Identifier: Apache-2.0

package cmd

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-19 -cflags "-O2 -g -Wall" -target amd64 pcapml ../bpf/pcapml.bpf.c -- -I../bpf/headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-19 -cflags "-O2 -g -Wall" -target amd64,arm64,mips gateway ../bpf/gateway.bpf.c -- -I../bpf/headers
