// SPDX-License-Identifier: Apache-2.0

//go:build ebpf

package cmd

import (
	"fmt"
	"os"
	"strings"
)

// cgroupResolver resolves cgroup v2 IDs to their filesystem paths.
// It caches results keyed by cgroup ID to avoid repeated /proc reads.
type cgroupResolver struct {
	cache map[uint64]string
}

func newCgroupResolver() *cgroupResolver {
	return &cgroupResolver{cache: make(map[uint64]string)}
}

// resolve returns a human-readable cgroup path for the given cgroup ID.
// It reads /proc/<pid>/cgroup on first encounter and caches by cgroup ID.
// If the process has already exited, falls back to "cgroup:<id>".
func (r *cgroupResolver) resolve(cgroupID uint64, pid uint32) string {
	if path, ok := r.cache[cgroupID]; ok {
		return path
	}
	path := readCgroupPath(pid)
	if path == "" {
		path = fmt.Sprintf("cgroup:%d", cgroupID)
	}
	r.cache[cgroupID] = path
	return path
}

// readCgroupPath reads /proc/<pid>/cgroup and extracts the cgroup v2 path.
// cgroup v2 lines have the format "0::<path>".
func readCgroupPath(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			return strings.TrimPrefix(line, "0::")
		}
	}
	return ""
}
