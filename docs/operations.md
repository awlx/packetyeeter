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
| Analyzer inspector | `-inspect-addr` | `127.0.0.1:9092` | Keep loopback unless placed behind trusted access controls. State-mutating routes are protected by a same-origin/DNS-rebinding guard; behind a reverse proxy, add the proxy hostname to `-inspect-trusted-hosts` so mutating requests are accepted. Read-only GETs are never gated. |
| Analyzer pprof | `-pprof-addr` | `:6060` when enabled | Enable only temporarily for diagnostics and bind securely. |
| Collector metrics | `-metrics-addr` | `:2112` | Scrape from Prometheus over a trusted network. |
| Collector management | `-socket` | `/var/run/packetyeeter-collector.sock` | Created with mode `0600` (owner-only); run `yeetctl` as the same user or relax with a group and chmod after start. |
| HAProxy SPOE | `-spoe-port` | `9876` | Expose only to the local HAProxy instance. |

## systemd hardening notes

The analyzer is userspace-only and can run with normal hardening such as `NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true`, and a narrow `ReadWritePaths=/var/lib/packetyeeter`.

The collector is intentionally less restricted because it loads eBPF, attaches XDP/TC programs, opens raw/network resources, and uses pinned kernel maps. It needs BPF/network capabilities and `LimitMEMLOCK=infinity`. Avoid adding hardening directives that hide devices, remove BPF capabilities, block network address families, or prevent kernel map/program access unless validated on the target kernel.

## Staged tuning

- Begin with analyzer `-dry-run`.
- Keep `-enable-high-cardinality-metrics=false` during normal operations; turn it on only for short diagnostic windows.
- Set allowlists for monitoring systems, load balancers, bastion hosts, health checks, and upstream trusted proxies.
- Watch `packetyeeter_*_blocks_total`, reputation scores, AI detections, SPOE queue depth/drops, and collector/analyzer logs before enabling enforcement.
- Per-IP and per-JA4 reputation penalties now accumulate (previously the per-IP/JA4 score caps defaulted to 0, clamping those penalties to a no-op; only ASN scoring accrued). On upgrade, expect IP/JA4 reputation scores to rise for sources that repeatedly trip detections, which can cross ban thresholds that were previously never reached. Re-baseline in `-dry-run`, review reputation scores and `packetyeeter_*_blocks_total`, and tune allowlists/thresholds before enabling enforcement.
- Treat UDP reflection campaign labels as observability metadata. The analyzer can distinguish common vectors such as DNS, NTP, SSDP, CLDAP, Memcached, and QUIC Initial only when existing signal metadata carries useful port or protocol hints; ambiguous UDP campaigns remain labeled `udp_flood`.
- Treat adaptive campaign baselines as rollout context, not enforcement. During analyzer startup or a new service/vector mix, `baseline_enough_samples=false` means the EWMA is still warming up; compare `baseline_current_rate`, `baseline_rate`, and `baseline_multiplier` only after enough samples have accumulated for that service key.
- The adaptive baseline caps how fast it can rise per observation (`MaxGrowthPerObservation`, default 1.5x) to resist slow-ramp attacks that try to normalize themselves into the baseline; if legitimate traffic grows unusually fast, the baseline may lag for a few observation cycles before catching up. See `docs/observability.md` for details and tuning guidance.
- Campaign/carpet-bombing detections now penalize reputation (representative sample IP/ASN, scaled by campaign severity) the same way regular detections do, instead of bypassing reputation entirely - repeated campaign involvement from the same source/ASN accumulates over time. This does not change `WouldBlock`/enforcement behavior for campaigns; they remain observe-only.
- On dual-stack hosts, the collector now emits IPv6 ICMP/UDP flood and
  incomplete-handshake signals (previously IPv4-only). Expect new IPv6
  detections after upgrading; stage with analyzer `-dry-run` and verify IPv6
  allowlists (health checks, monitoring, upstream proxies) before enforcing.
- Roll back by re-enabling dry-run or stopping collectors before changing eBPF-related systemd hardening.

## Breaking change: `-haproxy-port` removed

The collector no longer accepts `-haproxy-port`. It backed a HAProxy peer
(stick-table) listener that was never wired to anything, and it has been deleted
along with the flag.

Go's flag parser rejects unknown flags, so a collector started with
`-haproxy-port` exits immediately with status 2. Under `Restart=on-failure` this
is a crash loop, not a clean failure, so **update the units before installing the
new binary**:

1. Remove `HAPROXY_PORT=` from `/etc/default/packetyeeter-collector`.
2. Remove `-haproxy-port "$HAPROXY_PORT"` from `ExecStart=`.
3. Check for a drop-in that overrides `ExecStart=`. A drop-in shadows the main
   unit, so editing only the main unit leaves the flag in place:

   ```bash
   systemctl cat packetyeeter-collector | grep -n 'haproxy-port'
   ```

   That prints every file that still passes it, including
   `/etc/systemd/system/packetyeeter-collector.service.d/*.conf`.
4. `systemctl daemon-reload`, then install the binary and restart.

Verify the flag is gone from the resolved command before restarting:

```bash
systemctl show packetyeeter-collector -p ExecStart --value | grep -c haproxy-port  # expect 0
```

## Sustained-download detection rollout

Sustained-download detection selects on duration and breadth rather than rate,
so its thresholds cannot be inherited from rate-limit tuning. It ships disabled,
and enabling detection does not enable blocking.

1. Enable the collector inputs. Set `-egress-accounting` on one collector and
   confirm `packetyeeter_egress_volume_signals_total` and
   `packetyeeter_egress_bytes_reported_total` are advancing. Without this only
   the breadth/shape path can ever fire: HAProxy cannot report transferred bytes
   over SPOE, so eBPF TC egress counters are the only byte source.
   Raise `-egress-min-bytes` if the signal stream is noisier than expected.
2. Enable detection only. Start the analyzer with `-sustained-enabled` and
   without `-sustained-enforce`. Every decision is logged as
   "detect-only, not blocking" and counted under
   `packetyeeter_sustained_decisions_total{outcome="would_block"}`.
3. Tune from the inspector, not from guesswork. `GET /api/sustained` reports,
   per client, which thresholds it is under (`blockers`) and how close it is to
   each (`margins`, as a percentage). Sort with `?by=bytes|requests|resources|sections`.
   Clients sitting at 90-100% on every margin are the ones the thresholds are
   about to catch; review those before enforcing.
   - Note the two paths are independent. `path: "shape"` means breadth with no
     byte floor at all, which is the enumeration case; `path: "volume"` means
     bulk transfer. If ordinary deep usage (a CI job, a package mirror client)
     is landing in the shape path, lower
     `-sustained-max-resources-per-section-percent` rather than raising the
     resource minimum.
4. Watch capacity. A growing `packetyeeter_sustained_client_evictions_total`
   means more clients share the window than `-sustained-max-clients` allows, so
   detection is being applied to an arbitrary subset. Raise the ceiling before
   trusting the results.
5. Enforce on one analyzer. Add `-sustained-enforce`. Expect
   `packetyeeter_sustained_held_clients` to become nonzero and stay there:
   blocking removes the byte evidence that selected the client, so the hold is
   what keeps the block in place. A hold that never drains means blocked clients
   are not backing off; `-sustained-max-hold-seconds` bounds it regardless.
6. Keep the analyzer-wide kill switch reachable (see below). It is not specific
   to this detector, which is the point: if traffic is being blocked that should
   not be, stopping it should not require identifying the responsible detector
   first.

Allowlisted IPs are skipped entirely. Verified crawlers are not - they get their
request and byte floors multiplied by `-sustained-reputation-factor`, so a
verified crawler that starts mirroring the site is still caught. If a verified
crawler is being caught legitimately, allowlist it rather than raising the
factor for everyone.

## Runtime enforcement kill switch

`POST /api/enforcement/stop` on the analyzer's inspector suppresses every
enforcing command the analyzer would issue - from all detectors - while leaving
detection, scoring, metrics, and the reporting surfaces running.

```bash
curl -sS -X POST http://127.0.0.1:9092/api/enforcement/stop \
  -H 'Content-Type: application/json' \
  -d '{"reason":"INC-1234 blocking legitimate CI traffic"}'

curl -sS http://127.0.0.1:9092/api/enforcement
```

- It complements `-dry-run` rather than duplicating it. `-dry-run` is a
  deployment decision fixed at startup; this is an incident response reachable
  in seconds, without a restart and without editing a unit file.
- Relieving commands - unblock and allowlist - keep flowing. The switch is
  pulled precisely when a block is wrong, so suppressing the commands that undo
  a block would make the incident worse.
- It is one-way. Resuming enforcement requires a config change and a restart,
  which leaves a record of the decision. The state is not persisted, so a
  restart returns to whatever the deployed configuration says - if you stopped
  enforcement because a threshold is wrong, fix the threshold before restarting.
- It is same-origin guarded like every other mutating inspector endpoint, so the
  inspector must stay on loopback or behind trusted access controls (see
  "Listener exposure").
- Alert on `packetyeeter_enforcement_stopped == 1`. Because it survives until a
  restart, an unnoticed kill switch means the fleet has been silently
  detect-only, possibly for days. `packetyeeter_enforcement_suppressed_commands_total`
  shows how much enforcement is being withheld.

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
