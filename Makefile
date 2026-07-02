.PHONY: all proto collector analyzer clean install lint test

# Default target
all: proto collector analyzer

# Generate protobuf code
proto:
	@echo "Generating protobuf code..."
	cd api/proto && buf generate
	@echo "Verifying generated files exist..."
	ls -la api/proto/v1/*.pb.go

# Build collector daemon (eBPF, SPOE, HAProxy)
collector:
	@echo "Building packetyeeter-collector..."
	go build -ldflags="-s -w" -o packetyeeter-collector ./cmd/collector

# Build analyzer daemon (AI/ML, JA4DB, Reputation)
analyzer:
	@echo "Building packetyeeter-analyzer..."
	go build -ldflags="-s -w" -o packetyeeter-analyzer ./cmd/analyzer

# Build legacy combined daemon (for backwards compatibility)
legacy:
	@echo "Building packetyeeter (legacy combined)..."
	go build -ldflags="-s -w" -o packetyeeter .

# Build CLI tool
yeetctl:
	@echo "Building yeetctl..."
	go build -ldflags="-s -w" -o yeetctl ./cmd/yeetctl

# Install buf for proto generation
install-buf:
	go install github.com/bufbuild/buf/cmd/buf@latest
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Install dependencies
deps:
	go mod download
	go mod tidy

# Run tests
test:
	go test -v ./...

# Run linter
lint:
	golangci-lint run ./...

# Clean build artifacts
clean:
	rm -f packetyeeter packetyeeter-collector packetyeeter-analyzer yeetctl
	rm -rf api/proto/v1

# Build for Linux (cross-compile from macOS)
linux: proto
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o packetyeeter-collector-linux ./cmd/collector
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o packetyeeter-analyzer-linux ./cmd/analyzer

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
