FROM golang:1.26.4-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    linux-libc-dev \
    make \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN rm -f pkg/collector/ebpf/c/protector.bpf.o \
    && make install-buf \
    && make proto bpf analyzer collector

# analyzer: userspace-only "brain" image, no eBPF/root capabilities needed.
FROM debian:bookworm-slim AS analyzer

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/packetyeeter-analyzer /usr/local/bin/packetyeeter-analyzer

ENTRYPOINT ["packetyeeter-analyzer"]

# collector: loads XDP/TC eBPF and enforces blocks; needs to run privileged
# (or with NET_ADMIN/BPF/PERFMON caps) on the protected host's network
# namespace -- see docs/operations.md for the recommended systemd/capability
# setup instead of running this image unprivileged.
FROM debian:bookworm-slim AS collector

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/packetyeeter-collector /usr/local/bin/packetyeeter-collector

ENTRYPOINT ["packetyeeter-collector"]
