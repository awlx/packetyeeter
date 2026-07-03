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
- The adaptive baseline caps how fast it can rise per observation (`MaxGrowthPerObservation`, default 1.5x) to resist slow-ramp attacks that try to normalize themselves into the baseline; if legitimate traffic grows unusually fast, the baseline may lag for a few observation cycles before catching up. See `docs/observability.md` for details and tuning guidance.
- Campaign/carpet-bombing detections now penalize reputation (representative sample IP/ASN, scaled by campaign severity) the same way regular detections do, instead of bypassing reputation entirely - repeated campaign involvement from the same source/ASN accumulates over time. This does not change `WouldBlock`/enforcement behavior for campaigns; they remain observe-only.
- Roll back by re-enabling dry-run or stopping collectors before changing eBPF-related systemd hardening.

## Modern DDoS runbook

Use this workflow when campaign metrics or logs indicate a possible L3/L4 DDoS.
Campaign and carpet-bombing detections are observe-only aggregate signals; they
help operators understand blast radius and vector mix, but do not create block
commands on their own.

1. Confirm analyzer health and visibility. Check collector connectivity, signal
   queue pressure, `packetyeeter_active_attack_campaigns`, and recent
   `attack_campaign_observed` logs. If queues are dropping, treat the data as
   incomplete until backpressure is resolved.
2. Identify the dominant vector with
   `sum by (vector) (rate(packetyeeter_attack_campaign_detections_total[5m]))`.
   Interpret specific UDP labels as hints from existing port/protocol metadata:
   `dns_reflection`, `ntp_reflection`, `ssdp_reflection`, `cldap_reflection`,
   `memcached_reflection`, and `quic_initial_flood` are more specific than the
   fallback `udp_flood`.
3. Triage carpet-bombing breadth with
   `packetyeeter_carpet_bombing_detections_total{reason=...}` and the matching
   logs. Destination-subnet breadth usually points to distributed target
   selection; destination-port breadth may indicate service discovery or
   multi-service pressure; source breadth indicates distributed origin volume.
4. Compare the current campaign to adaptive service baselines. Ignore
   `enough_samples="false"` for enforcement decisions because the service key is
   still warming up. Once enough samples exist, use the p95 baseline multiplier
   and `packetyeeter_campaign_baseline_rate` to decide whether the campaign is
   unusual for that protocol/port bucket/vector.
5. Keep enforcement staged. Start or return to analyzer `-dry-run`, add or verify
   allowlists for health checks, trusted proxies, monitoring, and upstream
   providers, then canary enforcement on one collector before widening rollout.
6. Document the vector, affected services, baseline state, actions taken, and
   whether any block commands came from per-source detection paths rather than
   observe-only campaign aggregation.

## Prometheus example

An example scrape configuration is available in [`examples/prometheus-scrape.yml`](../examples/prometheus-scrape.yml). Adjust target hostnames and ports to match your deployment and keep scrape access on a trusted network.

Example alert rules for modern DDoS observations are available in
[`examples/prometheus-alerts.yml`](../examples/prometheus-alerts.yml).
