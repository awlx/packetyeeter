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
- Per-IP and per-JA4 reputation penalties accumulate. Analyzer defaults apply
  finite score caps (`-reputation-ip-score-cap=200`,
  `-reputation-ja4-score-cap=200`, `-reputation-asn-score-cap=500`; `0` =
  uncapped) so scores can still clear the ban threshold with headroom but cannot
  run away indefinitely. Re-baseline in `-dry-run`, review reputation scores and
  `packetyeeter_*_blocks_total`, and tune allowlists/thresholds/caps before
  enabling enforcement.
- Collector `-udp-frag-mode` defaults to `rate` (rate-limit fragmented UDP / IPv6
  fragments instead of hard-dropping them). Use `drop` only when restoring the
  legacy unconditional drop is intentional.
- Treat UDP reflection campaign labels as observability metadata. The analyzer can distinguish common vectors such as DNS, NTP, SSDP, CLDAP, Memcached, and QUIC Initial only when existing signal metadata carries useful port or protocol hints; ambiguous UDP campaigns remain labeled `udp_flood`.
- Treat adaptive campaign baselines as rollout context, not enforcement. During analyzer startup or a new service/vector mix, `baseline_enough_samples=false` means the EWMA is still warming up; compare `baseline_current_rate`, `baseline_rate`, and `baseline_multiplier` only after enough samples have accumulated for that service key.
- The adaptive baseline caps how fast it can rise per observation (`MaxGrowthPerObservation`, default 1.5x) to resist slow-ramp attacks that try to normalize themselves into the baseline; if legitimate traffic grows unusually fast, the baseline may lag for a few observation cycles before catching up. See `docs/observability.md` for details and tuning guidance.
- Campaign/carpet-bombing detections are observe-only: they do not mutate
  reputation for a representative sample IP/ASN. Use campaign metrics and
  inspector views for tuning; do not expect campaign membership alone to raise
  ban scores.
- On dual-stack hosts, the collector now emits IPv6 ICMP/UDP flood and
  incomplete-handshake signals (previously IPv4-only). Expect new IPv6
  detections after upgrading; stage with analyzer `-dry-run` and verify IPv6
  allowlists (health checks, monitoring, upstream proxies) before enforcing.
- Roll back by re-enabling dry-run or stopping collectors before changing eBPF-related systemd hardening.

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

## Scrub mode

`-mode scrub` turns a Linux server into an inline scrubber. Edge routers send
traffic for an attacked address to the node's outside port (`-i`); `xdp_scrub`
drops attack traffic with the same checks as host mode (blocked IPs, `-policy`,
bad TCP flags, fragment policy, ICMP/UDP rate limits) and forwards the rest out
of the inside port (`-inside-if`) at XDP speed. Replies take the normal path
and never cross the node.

```bash
sudo packetyeeter-collector -mode scrub -i eth0 -inside-if eth1 -dry-run
```

Requirements, checked at start-up (the collector refuses to start otherwise):

- Linux 5.15 or newer, and native XDP on both ports (`-allow-generic` for labs).
- `net.ipv4.ip_forward=1` and `net.ipv4.conf.<outside>.forwarding=1`, plus
  `net.ipv6.conf.all.forwarding=1` and `net.ipv6.conf.<outside>.forwarding=1`
  when the node has a global IPv6 address on either port or any IPv6 route
  (other than link-local/multicast) out of the inside port, e.g. a route via a
  link-local next hop. The kernel forwards whatever XDP cannot (no neighbour
  entry yet, TTL expiry, MTU, VLAN-tagged frames) and keeps forwarding if the
  collector stops. `bpf_fib_lookup` checks the outside port's own setting, so
  the per-port sysctls matter even with the global one set.
- `rp_filter` 0 or 2 on the outside port: attack sources are spoofed, and strict
  mode drops them in the kernel path.

Routing:

- Protected prefixes must be routed via the inside port only.
- The inside network must not learn the redirect route, or forwarded traffic
  loops back to the edge; `packetyeeter_scrub_ttl_expired_total` rising is the
  symptom.
- Multicast and link-local destinations, ARP and IPv6 neighbour discovery
  always reach the local stack unchecked, so routing protocols and neighbour
  resolution keep working.
- Unicast traffic to the node's own addresses (BGP and management addresses,
  VIPs on `lo`, port addresses) is checked against `blocked_ips` and `-policy`
  (honouring the allowlist and monitor mode) and otherwise passed to the local
  stack. The bad-flags, fragment and ICMP/UDP rate-limit checks are not
  applied: they are sized for forwarded traffic and would throttle the node's
  control plane. Up to 4096 addresses per family are tracked; start-up fails if
  the node has more, and later overflows are logged once until they clear.

Readiness and failure:

- `GET /readyz` on `-metrics-addr` returns 200 only while `xdp_scrub` is
  attached, the inside port is up and a redirect target, and forwarding is
  enabled; otherwise 503 with the reason. Use it to decide whether the node may
  be a next hop.
- On SIGTERM the node reports 503 for `-readyz-drain` before detaching, so
  traffic can move away first. The control plane (analyzer block commands,
  block expiry, `local_addrs` sync, incident reporting) keeps running during the
  drain; `xdp_scrub` is detached before `xdp_pass_inside` so in-flight
  redirects are not dropped.
- If the collector crashes, the kernel detaches XDP and keeps forwarding
  unscrubbed traffic: the node fails open, never blackholes.

Slow-path limit: packets that need the kernel (TTL <= 1, oversize with DF,
destinations without a neighbour entry, routes out of other ports, forwarding
disabled) are capped at `-scrub-slow-path-pps` (default 100000, 0 = unlimited)
across all CPUs, so floods aimed at the slow path cannot exhaust the kernel or
its neighbour table (a random-destination flood into a connected IPv6 /64).
The budget is split evenly over CPUs, so traffic concentrated on one RX queue
hits its share sooner. The tradeoff: while the cap is reached, legitimate
slow-path packets are dropped too, which delays neighbour resolution for new
destinations and suppresses ICMP errors (time exceeded, packet too big) until
the next second. VLAN-tagged traffic, which always takes the slow path, is not
counted. Watch `packetyeeter_scrub_slow_path_limited_total`; in `-dry-run`
over-limit packets are passed and only counted. Size the cap above the normal
slow-path rate (`rate(packetyeeter_scrub_packets_total{verdict="slow_path"})`).

Rollout: start with `-dry-run` (drops are logged as incidents and forwarded),
compare `packetyeeter_kernel_incidents_total` with expected attack traffic,
then remove `-dry-run`. Scrub nodes do not run SPOE, JA4H or egress accounting.

Incomplete-handshake signals work on scrub nodes too, tracked in XDP: replies
bypass the node, so a handshake counts as complete when the client's first ACK
arrives rather than after the server's SYN-ACK. Only SYNs the node actually
forwarded in XDP are tracked. Signals reach the analyzer after
`-handshake-timeout` (default `3s`) and use the same `-ddos-min-incomplete`
threshold as host mode. Handshake RTT (JA4L) needs the SYN-ACK and is not
available in scrub mode.

A connection's SYN and first ACK must cross the same scrub node. With several
nodes, keep ECMP hashing on the 5-tuple, and expect a short burst of
incomplete-handshake signals whenever flows move: a node draining or joining,
or the redirect being withdrawn. A SYN lost between the node and the victim is
retransmitted after about 1s and again after 3s, so on a congested victim link
some legitimate clients exceed the default timeout; raise
`-handshake-timeout` if that shows up as false positives.

Labs on veth pairs: the veth receiving redirected frames needs GRO enabled
(`ethtool -K <peer> gro on`) on its peer, and locally generated test traffic
needs tx checksum offload disabled on the sender. `make e2e-scrub-test` sets
this up.

### Runtime rules

Scrub collectors apply match rules received on the analyzer stream as
`COMMAND_SET_RULES` (a `RuleSetDelta`: rules to upsert by `id`, ids to
remove). The analyzer API that sends them is not available yet. A rule matches
traffic for its `dst_prefix` on any combination of protocols, source and
destination port ranges, IP total length, TCP flags (`flags & mask ==
value`), fragment state and up to 8 source prefixes, and then:

- `DROP` drops the packet (logged as incident `rule_match`);
- `RATE_LIMIT` drops what exceeds `rate_pps` (one budget per rule shared by
  all CPUs; 100ms windows, 1s below 100 pps);
- `PASS` forwards it without the per-source checks (blocked IPs, `-policy`,
  rate limits, bad TCP flags).

Rules run after the allowlist and before the per-source checks; the first
matching rule by `priority` (lower first, ties by `id`) decides, whatever the
prefix lengths. `-dry-run` counts and logs rule drops but forwards. A
per-source `-policy` `monitor` entry does not exempt a source from rules; the
allowlist does. Traffic to the node's own, multicast and link-local addresses
is never matched against rules.

Limits: 4096 rules per address family, 8 port ranges per direction, 8 source
prefixes, and 32 rules covering any one destination. A delta that breaks a
limit, or contains any invalid rule, is rejected whole and logged; the
previous rules stay active. `expires_at` is required; expired rules are removed
within a second. Rules live in memory only: after a collector restart they are
back once the analyzer resends them.

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
