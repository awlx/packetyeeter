#!/bin/bash
set -e

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <host> [component] [options]"
    echo "  component: collector, analyzer, both (default: both)"
    echo ""
    echo "Options:"
    echo "  --install-deps      Install build dependencies first"
    echo "  --install-service   Install and enable systemd services"
    echo "  --regen-proto       Regenerate protobuf files before building"
    echo "  -i, --interface     Network interface for collector (default: eth0)"
    echo "  --analyzer-addr     Analyzer address for collector (default: 127.0.0.1:9090)"
    echo "  --listen-addr       Listen address for analyzer (default: 0.0.0.0:9090)"
    echo "  --metrics-addr      Metrics listen address (default: :9091 analyzer, :2112 collector)"
    echo ""
    echo "Examples:"
    echo "  $0 webfrontend01.example.com both -i ens192 --install-service"
    echo "  $0 webfrontend01.example.com collector -i eth0 --analyzer-addr 10.0.0.5:9090"
    echo "  $0 analyzer.example.com analyzer --listen-addr 0.0.0.0:9090"
    echo "  $0 webfrontend01.example.com both --install-deps --install-service"
    exit 1
fi

HOST=$1
COMPONENT=${2:-both}
# Check if second arg looks like a flag, if so reset to "both"
if [[ "$COMPONENT" == -* ]]; then
    COMPONENT="both"
fi

# Installation paths
SRC_DIR="/usr/local/src/packetyeeter"
COLLECTOR_BIN_DIR="/opt/packetyeeter/collector"
ANALYZER_BIN_DIR="/opt/packetyeeter/analyzer"

# Defaults
INTERFACE="eth0"
ANALYZER_ADDR="127.0.0.1:9090"
LISTEN_ADDR="0.0.0.0:9090"
METRICS_ADDR=""
INSTALL_DEPS=false
INSTALL_SERVICE=false
REGEN_PROTO=false

# Parse options
shift  # remove HOST
if [ "$COMPONENT" != "both" ] && [ "$COMPONENT" != "collector" ] && [ "$COMPONENT" != "analyzer" ]; then
    # not a valid component, treat it as a flag
    set -- "$COMPONENT" "$@"
    COMPONENT="both"
else
    shift  # remove COMPONENT
fi

while [[ $# -gt 0 ]]; do
    case $1 in
        --install-deps)
            INSTALL_DEPS=true
            shift
            ;;
        --install-service)
            INSTALL_SERVICE=true
            shift
            ;;
        --regen-proto)
            REGEN_PROTO=true
            shift
            ;;
        -i|--interface)
            INTERFACE="$2"
            shift 2
            ;;
        --analyzer-addr)
            ANALYZER_ADDR="$2"
            shift 2
            ;;
        --listen-addr)
            LISTEN_ADDR="$2"
            shift 2
            ;;
        --metrics-addr)
            METRICS_ADDR="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== PacketYeeter Split Deploy ==="
echo "Target: $HOST"
echo "Component: $COMPONENT"
if [ "$COMPONENT" = "both" ] || [ "$COMPONENT" = "collector" ]; then
    echo "Interface: $INTERFACE"
    echo "Analyzer: $ANALYZER_ADDR"
fi
if [ "$COMPONENT" = "both" ] || [ "$COMPONENT" = "analyzer" ]; then
    echo "Listen: $LISTEN_ADDR"
    if [ -n "$METRICS_ADDR" ]; then
        echo "Metrics: $METRICS_ADDR"
    fi
fi
echo ""

# Sync source files to remote
echo "Syncing source files to $HOST:$SRC_DIR..."
ssh $HOST "sudo mkdir -p $SRC_DIR && sudo chown \$(whoami): $SRC_DIR"
rsync -avz --delete --exclude '.git' --exclude 'packetyeeter' --exclude 'packetyeeter-collector' \
    --exclude 'packetyeeter-analyzer' --exclude 'yeetctl' --exclude 'yeetexplorer' \
    --exclude '*.o' . $HOST:$SRC_DIR/

# Optionally install dependencies if flag provided
if [ "$INSTALL_DEPS" = true ]; then
    echo "Checking/Installing dependencies on remote host..."
    ssh -t "$HOST" "
        echo 'Stopping unattended-upgrades to release lock...'
        sudo systemctl stop unattended-upgrades.service || true
        
        echo 'Running apt update/install (waiting up to 60s for lock)...'
        sudo apt-get -o DPkg::Lock::Timeout=60 update && \
        sudo apt-get -o DPkg::Lock::Timeout=60 install -y bpfcc-tools libbpfcc libbpfcc-dev clang llvm libbpf-dev linux-headers-\$(uname -r) wget

        echo 'Installing/Ensuring Go 1.25.6...'
        if ! /usr/local/go/bin/go version 2>/dev/null | grep -q 'go1.25.6'; then
            echo 'Downloading Go 1.25.6...'
            wget -q https://go.dev/dl/go1.25.6.linux-amd64.tar.gz
            sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.25.6.linux-amd64.tar.gz
            rm go1.25.6.linux-amd64.tar.gz
        fi
    "
fi

# Always install/update ONNX Runtime for ML support
echo "Installing/Updating ONNX Runtime..."
ssh "$HOST" "
    if [ ! -d /opt/onnxruntime ]; then
        echo 'Installing ONNX Runtime 1.23.2 for ML support...'
        cd /tmp
        wget -q https://github.com/microsoft/onnxruntime/releases/download/v1.23.2/onnxruntime-linux-x64-1.23.2.tgz
        tar xzf onnxruntime-linux-x64-1.23.2.tgz
        sudo mv onnxruntime-linux-x64-1.23.2 /opt/onnxruntime
        rm -f onnxruntime-linux-x64-1.23.2.tgz
        
        echo '/opt/onnxruntime/lib' | sudo tee /etc/ld.so.conf.d/onnxruntime.conf
        sudo ldconfig
        
        echo '✓ ONNX Runtime installed to /opt/onnxruntime'
    else
        echo '✓ ONNX Runtime already installed'
    fi
"

# Optionally regenerate protobuf files
if [ "$REGEN_PROTO" = true ]; then
    echo "Regenerating protobuf files on remote host..."
    ssh -t "$HOST" "
        export PATH=/usr/local/go/bin:\$PATH
        cd $SRC_DIR

        # Install protoc if not present
        if ! command -v protoc &> /dev/null; then
            echo 'Installing protoc...'
            PROTOC_VERSION=25.1
            wget -q https://github.com/protocolbuffers/protobuf/releases/download/v\${PROTOC_VERSION}/protoc-\${PROTOC_VERSION}-linux-x86_64.zip
            sudo unzip -o protoc-\${PROTOC_VERSION}-linux-x86_64.zip -d /usr/local
            rm protoc-\${PROTOC_VERSION}-linux-x86_64.zip
        fi

        # Install Go protoc plugins
        echo 'Installing protoc-gen-go plugins...'
        go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
        go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
        export PATH=\$PATH:\$(go env GOPATH)/bin

        # Regenerate
        echo 'Regenerating proto files...'
        protoc --go_out=. --go_opt=paths=source_relative \
               --go-grpc_out=. --go-grpc_opt=paths=source_relative \
               api/proto/v1/packetyeeter.proto

        echo 'Proto files regenerated'
    "
fi

# Build on remote host
echo "Building on remote host $HOST..."

# Always regenerate proto files first
BUILD_CMDS="export GO111MODULE=on GOFLAGS=-mod=mod PATH=/usr/local/go/bin:\$HOME/go/bin:\$PATH && cd $SRC_DIR && \
    rm -f api/proto/packetyeeter.proto packetyeeter.pb.go packetyeeter_grpc.pb.go && \
    echo 'Running go mod download and tidy...' && \
    go mod download && go mod tidy && \
    echo 'Installing buf and protoc-gen-go tools...' && \
    go install github.com/bufbuild/buf/cmd/buf@latest && \
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest && \
    echo 'Regenerating proto files...' && \
    export PATH=/usr/local/go/bin:\$HOME/go/bin:\$PATH && make proto && \
    echo 'Verifying generated proto files...' && \
    ls -la api/proto/v1/*.pb.go"

if [ "$COMPONENT" = "both" ] || [ "$COMPONENT" = "collector" ]; then
    BUILD_CMDS="$BUILD_CMDS && echo 'Compiling BPF...' && \
        clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c pkg/collector/ebpf/c/protector.bpf.c -o pkg/collector/ebpf/c/protector.bpf.o && \
        echo 'Building collector...' && \
        go build -o packetyeeter-collector ./cmd/collector"
fi

if [ "$COMPONENT" = "both" ] || [ "$COMPONENT" = "analyzer" ]; then
    BUILD_CMDS="$BUILD_CMDS && echo 'Building analyzer with ONNX support...' && \
        CGO_ENABLED=1 CGO_CFLAGS='-I/opt/onnxruntime/include' CGO_LDFLAGS='-L/opt/onnxruntime/lib -Wl,-rpath,/opt/onnxruntime/lib' \
        go build -o packetyeeter-analyzer ./cmd/analyzer"
fi

ssh "$HOST" "$BUILD_CMDS"

# Write configuration files and install services
if [ "$INSTALL_SERVICE" = true ]; then
    echo ""
    echo "Installing services and writing configuration..."

    if [ "$COMPONENT" = "both" ] || [ "$COMPONENT" = "collector" ]; then
        echo "Configuring collector service..."
        # Generate config file locally and copy via cat
        cat << EOF | ssh "$HOST" "sudo tee /etc/default/packetyeeter-collector > /dev/null"
# PacketYeeter Collector Configuration
# Auto-generated by deploy-split.sh

# Network interface to attach eBPF programs to
INTERFACE=$INTERFACE

# Address of the analyzer daemon (host:port)
ANALYZER_ADDR=$ANALYZER_ADDR

# HAProxy peer protocol port
HAPROXY_PORT=8765

# SPOE agent port
SPOE_PORT=9876

# Unix socket for CLI management
SOCKET_PATH=/var/run/packetyeeter-collector.sock

# GeoIP ASN database path
GEOIP_ASN_PATH=/var/lib/GeoIP/GeoLite2-ASN.mmdb

# Block duration for IPs (e.g., 300s, 5m, 1h)
BLOCK_DURATION=300s

# TCP handshake timeout
HANDSHAKE_TIMEOUT=10s

# SYN flood detection threshold (incomplete handshakes)
HANDSHAKES_THRESHOLD=1000

# ICMP rate threshold per IP
ICMP_THRESHOLD=10000

# UDP rate threshold per IP
UDP_THRESHOLD=10000
EOF

        ssh "$HOST" "sudo mkdir -p $COLLECTOR_BIN_DIR && \
            sudo cp $SRC_DIR/packetyeeter-collector $COLLECTOR_BIN_DIR/ && \
            sudo cp $SRC_DIR/packetyeeter-collector.service /etc/systemd/system/ && \
            sudo systemctl daemon-reload && \
            sudo systemctl enable packetyeeter-collector"
        echo "Collector service installed and enabled"
    fi

    if [ "$COMPONENT" = "both" ] || [ "$COMPONENT" = "analyzer" ]; then
        echo "Configuring analyzer service..."
        # Generate config file locally and copy via cat
        cat << EOF | ssh "$HOST" "sudo tee /etc/default/packetyeeter-analyzer > /dev/null"
# PacketYeeter Analyzer Configuration
# Auto-generated by deploy-split.sh

# gRPC listen address for collectors
LISTEN_ADDR=$LISTEN_ADDR

# InfluxDB connection
INFLUX_URL=$INFLUX_URL
INFLUX_DB=packetyeeter

# GeoIP ASN database path
GEOIP_ASN_PATH=/var/lib/GeoIP/GeoLite2-ASN.mmdb

# Shodan API key for threat intelligence (optional)
# SHODAN_API_KEY=your_api_key_here

# Reputation threshold (0-100)
# REP_THRESHOLD=75

# Monitor mode (dry run) - set to "-dry-run" to enable
# DRY_RUN=-dry-run
EOF

        ssh "$HOST" "sudo mkdir -p $ANALYZER_BIN_DIR && \
            sudo cp $SRC_DIR/packetyeeter-analyzer $ANALYZER_BIN_DIR/ && \
            sudo cp $SRC_DIR/packetyeeter-analyzer.service /etc/systemd/system/ && \
            sudo systemctl daemon-reload && \
            sudo systemctl enable packetyeeter-analyzer"
        echo "Analyzer service installed and enabled"
    fi

    echo ""
    echo "=== Services Installed ==="
    if [ "$COMPONENT" = "both" ] || [ "$COMPONENT" = "collector" ]; then
        echo "Start collector: sudo systemctl start packetyeeter-collector"
    fi
    if [ "$COMPONENT" = "both" ] || [ "$COMPONENT" = "analyzer" ]; then
        echo "Start analyzer:  sudo systemctl start packetyeeter-analyzer"
    fi
else
    echo ""
    echo "=== Build Complete ==="
    echo ""
    echo "To install services, re-run with --install-service flag, or manually:"

    if [ "$COMPONENT" = "both" ] || [ "$COMPONENT" = "collector" ]; then
        echo ""
        echo "Collector:"
        echo "  ssh $HOST"
        echo "  sudo mkdir -p $COLLECTOR_BIN_DIR"
        echo "  sudo cp $SRC_DIR/packetyeeter-collector $COLLECTOR_BIN_DIR/"
        echo "  sudo cp $SRC_DIR/packetyeeter-collector.service /etc/systemd/system/"
        echo "  sudo cp $SRC_DIR/packetyeeter-collector.default /etc/default/packetyeeter-collector"
        echo "  # Edit /etc/default/packetyeeter-collector: set INTERFACE=$INTERFACE"
        echo "  sudo systemctl daemon-reload && sudo systemctl enable --now packetyeeter-collector"
    fi

    if [ "$COMPONENT" = "both" ] || [ "$COMPONENT" = "analyzer" ]; then
        echo ""
        echo "Analyzer:"
        echo "  ssh $HOST"
        echo "  sudo mkdir -p $ANALYZER_BIN_DIR"
        echo "  sudo cp $SRC_DIR/packetyeeter-analyzer $ANALYZER_BIN_DIR/"
        echo "  sudo cp $SRC_DIR/packetyeeter-analyzer.service /etc/systemd/system/"
        echo "  sudo cp $SRC_DIR/packetyeeter-analyzer.default /etc/default/packetyeeter-analyzer"
        echo "  sudo systemctl daemon-reload && sudo systemctl enable --now packetyeeter-analyzer"
    fi
fi

echo ""
echo "To run manually:"
if [ "$COMPONENT" = "both" ] || [ "$COMPONENT" = "collector" ]; then
    echo "  Collector: ssh -t $HOST 'sudo $COLLECTOR_BIN_DIR/packetyeeter-collector -i $INTERFACE -analyzer-addr $ANALYZER_ADDR'"
fi
if [ "$COMPONENT" = "both" ] || [ "$COMPONENT" = "analyzer" ]; then
    echo "  Analyzer:  ssh -t $HOST 'sudo $ANALYZER_BIN_DIR/packetyeeter-analyzer -listen-addr $LISTEN_ADDR'"
fi
