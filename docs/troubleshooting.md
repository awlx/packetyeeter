# Troubleshooting

This guide covers common build, eBPF, deployment, and runtime issues.

## Build issues

### `protector.bpf.o: no such file or directory`

The collector embeds the compiled eBPF object. Build it before collector builds or full tests:

```bash
make bpf
make collector
```

On non-Linux hosts, use `make analyzer`, `make yeetctl`, or `make portable-test`; full collector builds need Linux eBPF tooling.

### `linux/bpf.h` or libbpf headers are missing

Install kernel headers and libbpf development packages for the target host. On Debian/Ubuntu-like systems:

```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r)
```

### eBPF compile fails with the wrong target architecture

`make bpf` derives `BPF_ARCH` from `uname -m`. Override it if cross-building or using a non-standard toolchain:

```bash
make bpf BPF_ARCH=x86
make bpf BPF_ARCH=arm64
```

## Collector startup issues

### Permission denied loading BPF or attaching XDP/TC

The collector must run as root or with the capabilities needed for eBPF and network attachment. The packaged unit grants:

```text
CAP_SYS_ADMIN CAP_NET_ADMIN CAP_BPF CAP_PERFMON CAP_NET_RAW
LimitMEMLOCK=infinity
```

Do not harden the collector with `PrivateDevices=true`, restrictive network namespaces, or capability drops unless you have verified BPF load, XDP attach, TC attach, and map access still work on the target kernel.

### Interface not found or XDP attach fails

Confirm the configured interface exists and supports the requested attachment mode:

```bash
ip link show
sudo ./packetyeeter-collector -i eth0 -analyzer-addr 127.0.0.1:9090 -v
```

Start on a non-production interface or maintenance window when testing new NICs, drivers, or kernels.

### Collector cannot connect to analyzer

Verify the analyzer gRPC listener, firewall rules, and collector `-analyzer-addr`:

```bash
ss -ltnp | grep 9090
journalctl -u packetyeeter-analyzer -n 100 --no-pager
journalctl -u packetyeeter-collector -n 100 --no-pager
```

## Runtime and operations

### Unexpected blocks or suspected false positives

Run the analyzer in dry-run mode while tuning:

```bash
packetyeeter-analyzer -dry-run -listen-addr 0.0.0.0:9090
```

Use allowlists for control-plane, monitoring, bastion, and trusted upstream CIDRs. Roll out enforcement gradually after reviewing logs, metrics, and `yeetctl list` output.

### Metrics or inspector are reachable from untrusted networks

Metrics endpoints and the analyzer inspector do not provide authentication. Bind them to loopback or trusted management networks, or place them behind firewall/VPN controls:

```bash
METRICS_ADDR=127.0.0.1:9091
EXTRA_ARGS="-inspect-addr 127.0.0.1:9092"
```

Only enable `-enable-pprof` temporarily and bind it to a trusted address.

### High-cardinality metrics are causing Prometheus pressure

Keep `-enable-high-cardinality-metrics=false` unless you need per-IP or per-fingerprint diagnostics. If enabled, use short retention or restricted scraping for the diagnostic job.

### Management socket access fails

The collector and `yeetctl` must use the same socket path. The default is `/var/run/packetyeeter-collector.sock`:

```bash
sudo ./yeetctl -sock /var/run/packetyeeter-collector.sock list
```

Keep the socket local and restrict filesystem permissions to trusted operators.
