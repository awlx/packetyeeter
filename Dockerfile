# Build Stage
FROM golang:1.23-bookworm AS builder

# Install libbcc dependencies
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    libbcc-dev \
    kernel-headers-generic || true

WORKDIR /app

# Copy Config
COPY go.mod go.sum ./
RUN go mod download

# Copy Source
COPY src/ ./src/

# Build
# CGO_ENABLED=1 is required for gobpf
RUN CGO_ENABLED=1 go build -o packetyeeter src/main.go

# Runtime Stage
FROM debian:bookworm-slim

# Install runtime libs
RUN apt-get update && apt-get install -y \
    libbcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary
COPY --from=builder /app/packetyeeter /usr/local/bin/packetyeeter
# Copy BPF source (needed at runtime for compilation)
COPY --from=builder /app/src/bpf /app/src/bpf

# Run
CMD ["packetyeeter", "-i", "eth0"]
