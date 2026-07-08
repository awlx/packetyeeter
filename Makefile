GO ?= go
CLANG ?= clang
GO_BIN := $(shell $(GO) env GOPATH)/bin
BUF ?= $(GO_BIN)/buf
BUF_VERSION ?= v1.65.0
PROTOC_GEN_GO_VERSION ?= v1.36.11
PROTOC_GEN_GO_GRPC_VERSION ?= v1.6.0
NFPM ?= $(GO_BIN)/nfpm
NFPM_VERSION ?= v2.41.1

BPF_SRC := pkg/collector/ebpf/c/protector.bpf.c
BPF_OBJ := pkg/collector/ebpf/c/protector.bpf.o
BPF_ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_CFLAGS ?= -I/usr/include/$(shell gcc -dumpmachine 2>/dev/null)

DIST_DIR := dist

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PKG_VERSION := $(patsubst v%,%,$(VERSION))
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X PacketYeeter/pkg/buildinfo.Version=$(VERSION) \
	-X PacketYeeter/pkg/buildinfo.Commit=$(COMMIT) \
	-X PacketYeeter/pkg/buildinfo.BuildDate=$(BUILD_DATE)

.PHONY: all proto bpf collector analyzer yeetctl clean install-buf install-nfpm deps lint test portable-test e2e-test linux install-services run-collector run-analyzer dist-binaries packages

# Default target
all: proto collector analyzer

# Generate protobuf code
proto:
	@echo "Generating protobuf code..."
	cd api/proto && PATH="$(GO_BIN):$$PATH" $(BUF) generate
	@echo "Verifying generated files exist..."
	ls -la api/proto/v1/*.pb.go

# Compile the eBPF object embedded by pkg/collector/ebpf/loader.go.
bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	@echo "Compiling eBPF object..."
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_ARCH) $(BPF_CFLAGS) -c $< -o $@

# Build collector daemon (eBPF, SPOE, HAProxy)
collector: proto bpf
	@echo "Building packetyeeter-collector..."
	$(GO) build -ldflags="$(LDFLAGS)" -o packetyeeter-collector ./cmd/collector

# Build analyzer daemon (AI/ML, JA4DB, Reputation)
analyzer: proto
	@echo "Building packetyeeter-analyzer..."
	$(GO) build -ldflags="$(LDFLAGS)" -o packetyeeter-analyzer ./cmd/analyzer

# Build CLI tool
yeetctl: proto
	@echo "Building yeetctl..."
	$(GO) build -ldflags="$(LDFLAGS)" -o yeetctl ./cmd/yeetctl

# Install buf for proto generation
install-buf:
	$(GO) install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)

# Install nfpm for building .deb packages
install-nfpm:
	$(GO) install github.com/goreleaser/nfpm/v2/cmd/nfpm@$(NFPM_VERSION)

# Install dependencies
deps:
	$(GO) mod download
	$(GO) mod tidy

# Run tests
test: proto
	$(GO) test -v ./...

# Run portable tests that do not require Linux eBPF support.
portable-test: proto
	$(GO) test -v ./pkg/analyzer/... ./pkg/ml/... ./pkg/integration_test ./pkg/collector ./cmd/yeetctl

# Run end-to-end tests that spawn a real haproxy binary to validate the
# collector's HAProxy peer-protocol listener and SPOE agent against actual
# haproxy wire behavior. Requires `haproxy` on PATH. Does not require Linux
# eBPF support since these tests exercise the HAProxy integration layer
# behind a test double instead of the real kernel maps.
e2e-test: proto
	$(GO) test -tags e2e -v ./pkg/collector/haproxy/...

# Run the Linux/eBPF kernel-enforcement e2e test. Requires root (to
# load/attach the real XDP program) and a Linux kernel with BPF support;
# not runnable on macOS/portable environments. See pkg/collector/ebpf_e2e_test.go
# for exactly what this does and does not verify.
e2e-ebpf-test: proto bpf
	sudo -E $(GO) test -tags e2e_ebpf -run TestKernelBlockEnforcement -v ./pkg/collector/...

# Run linter
lint:
	golangci-lint run ./...

# Clean build artifacts
clean:
	rm -f packetyeeter packetyeeter-collector packetyeeter-analyzer yeetctl
	rm -f packetyeeter-collector-linux packetyeeter-analyzer-linux
	rm -f $(BPF_OBJ)
	rm -rf $(DIST_DIR)

# Build for Linux (cross-compile from macOS)
linux: proto bpf
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags="$(LDFLAGS)" -o packetyeeter-collector-linux ./cmd/collector
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags="$(LDFLAGS)" -o packetyeeter-analyzer-linux ./cmd/analyzer

# Install systemd service files
install-services:
	sudo cp packetyeeter-collector.service /etc/systemd/system/
	sudo cp packetyeeter-analyzer.service /etc/systemd/system/
	sudo systemctl daemon-reload

# Development: run collector locally
run-collector: collector
	sudo ./packetyeeter-collector -i lo -analyzer-addr localhost:9100

# Development: run analyzer locally
run-analyzer: analyzer
	./packetyeeter-analyzer -listen-addr 0.0.0.0:9100

# Cross-compile release binaries into dist/. The collector's eBPF object
# is built for the host architecture (see BPF_ARCH above) and the
# analyzer links against onnxruntime via cgo, so neither can be easily
# cross-compiled without a matching cross toolchain + arch-specific
# onnxruntime library; both are built amd64-only here (matching the
# linux/amd64 CI runner). yeetctl, yeetexplorer, and labeler are pure Go
# (CGO_ENABLED=0) and cross-compile cleanly for both amd64 and arm64.
dist-binaries: proto bpf
	@mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/packetyeeter-collector-linux-amd64 ./cmd/collector
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/packetyeeter-analyzer-linux-amd64 ./cmd/analyzer
	for arch in amd64 arm64; do \
		GOOS=linux GOARCH=$$arch CGO_ENABLED=0 $(GO) build -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/yeetctl-linux-$$arch ./cmd/yeetctl; \
		GOOS=linux GOARCH=$$arch CGO_ENABLED=0 $(GO) build -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/yeetexplorer-linux-$$arch ./cmd/yeetexplorer; \
		GOOS=linux GOARCH=$$arch CGO_ENABLED=0 $(GO) build -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/labeler-linux-$$arch ./cmd/labeler; \
	done
	cd $(DIST_DIR) && sha256sum packetyeeter-* yeetctl-* yeetexplorer-* labeler-* > SHA256SUMS

# Build .deb packages for the collector and analyzer daemons (amd64
# only, see dist-binaries for why). Requires the binaries to be built
# natively at the repo root first and nfpm installed (`make install-nfpm`).
packages: collector analyzer
	@mkdir -p $(DIST_DIR)
	VERSION=$(PKG_VERSION) ARCH=amd64 $(NFPM) package --config packaging/nfpm/collector.yaml --packager deb --target $(DIST_DIR)/
	VERSION=$(PKG_VERSION) ARCH=amd64 $(NFPM) package --config packaging/nfpm/analyzer.yaml --packager deb --target $(DIST_DIR)/
