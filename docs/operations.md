# Operations Guide

Use this checklist when deploying PacketYeeter into production-like environments.

## Deployment sequence

1. Build and deploy the analyzer first.
2. Start the analyzer with `-dry-run` so detections update logs and metrics without sending BLOCK commands.
3. Deploy one collector on a canary host with conservative thresholds and explicit allowlists for trusted networks.
4. Review structured logs, Prometheus metrics, and `yeetctl list`.
5. Tune thresholds and allowlists, then expand to a small host batch.
6. Disable dry-run only after canary behavior is understood.

## Listener exposure

Default listeners are convenient for labs but should be deliberately bound in production.

| Component | Listener | Default | Guidance |
| :--- | :--- | :--- | :--- |
| Analyzer gRPC | `-listen-addr` | `0.0.0.0:9090` | Expose only to collectors over trusted networks or firewall rules. |
| Analyzer metrics | `-metrics-addr` | `:9091` | Bind to loopback/management networks or restrict with firewall/VPN. |
| Analyzer inspector | `-inspect-addr` | `127.0.0.1:9092` | Keep loopback unless placed behind trusted access controls. |
| Analyzer pprof | `-pprof-addr` | `:6060` when enabled | Enable only temporarily for diagnostics and bind securely. |
| Collector metrics | `-metrics-addr` | `:2112` | Scrape from Prometheus over a trusted network. |
| Collector management | `-socket` | `/var/run/packetyeeter-collector.sock` | Keep local and permission-restricted. |
| HAProxy peer/SPOE | `-haproxy-port`, `-spoe-port` | `8765`, `9876` | Expose only to trusted HAProxy peers. |

## systemd hardening notes

The analyzer is userspace-only and can run with normal hardening such as `NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true`, and a narrow `ReadWritePaths=/var/lib/packetyeeter`.

The collector is intentionally less restricted because it loads eBPF, attaches XDP/TC programs, opens raw/network resources, and uses pinned kernel maps. It needs BPF/network capabilities and `LimitMEMLOCK=infinity`. Avoid adding hardening directives that hide devices, remove BPF capabilities, block network address families, or prevent kernel map/program access unless validated on the target kernel.

## Staged tuning

- Begin with analyzer `-dry-run`.
- Keep `-enable-high-cardinality-metrics=false` during normal operations; turn it on only for short diagnostic windows.
- Set allowlists for monitoring systems, load balancers, bastion hosts, health checks, and upstream trusted proxies.
- Watch `packetyeeter_*_blocks_total`, reputation scores, AI detections, SPOE queue depth/drops, and collector/analyzer logs before enabling enforcement.
- Treat UDP reflection campaign labels as observability metadata. The analyzer can distinguish common vectors such as DNS, NTP, SSDP, CLDAP, Memcached, and QUIC Initial only when existing signal metadata carries useful port or protocol hints; ambiguous UDP campaigns remain labeled `udp_flood`.
- Treat adaptive campaign baselines as rollout context, not enforcement. During analyzer startup or a new service/vector mix, `baseline_enough_samples=false` means the EWMA is still warming up; compare `baseline_current_rate`, `baseline_rate`, and `baseline_multiplier` only after enough samples have accumulated for that service key.
- Roll back by re-enabling dry-run or stopping collectors before changing eBPF-related systemd hardening.

## Prometheus example

An example scrape configuration is available in [`examples/prometheus-scrape.yml`](../examples/prometheus-scrape.yml). Adjust target hostnames and ports to match your deployment and keep scrape access on a trusted network.
