.PHONY: all generate build build-full build-offline build-offline-pcap clean vmlinux test

VMLINUX_H := bpf/headers/vmlinux.h
BPFTOOL   ?= $(shell command -v bpftool 2>/dev/null || echo /usr/sbin/bpftool)
UNAME_S   := $(shell uname -s)

# eBPF capture requires Linux + bpftool; everything else gets offline-only build
ifeq ($(UNAME_S),Linux)
    ifneq ($(shell command -v $(BPFTOOL) 2>/dev/null),)
        DEFAULT_BUILD := build
    else
        DEFAULT_BUILD := build-offline
    endif
else
    DEFAULT_BUILD := build-offline
endif

all: $(DEFAULT_BUILD)
	@echo "Built with target: $(DEFAULT_BUILD)"

# Generate vmlinux.h from the running kernel's BTF
vmlinux: $(VMLINUX_H)

$(VMLINUX_H):
	@echo "Generating vmlinux.h..."
	@mkdir -p bpf/headers
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

# Compile eBPF C and generate Go bindings (into cmd/ package)
generate: $(VMLINUX_H)
	cd cmd && go generate ./...
	@# Add ebpf build tag to generated files so they are excluded from offline builds
	@for f in cmd/pcapml_*.go cmd/gateway_*.go; do \
		if [ -f "$$f" ] && ! head -1 "$$f" | grep -q 'go:build.*ebpf'; then \
			sed -i '1s|^//go:build \(.*\)|//go:build ebpf \&\& (\1)|' "$$f"; \
		fi; \
	done

# Build with eBPF live capture support (Linux only, requires bpftool)
build: generate
	go build -tags ebpf -o pcapml .

# Build with both eBPF live capture and pcap/label support
build-full: generate
	go build -tags "ebpf pcap" -o pcapml .

# Build offline-only (label, split, sort, strip — no live capture)
build-offline:
	go build -o pcapml .

# Build offline with pcap/label support
build-offline-pcap:
	go build -tags pcap -o pcapml .

test:
	go test -count=1 ./...

clean:
	rm -f pcapml
	rm -f cmd/pcapml_*.go cmd/pcapml_*.o
	rm -f cmd/gateway_*.go cmd/gateway_*.o
	rm -f $(VMLINUX_H)
	go clean -testcache
