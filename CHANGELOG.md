# PacketYeeter Changelog

## 2026-10-04 - Scrub handshake maps sized for online CPUs

- New collector flag `-scrub-handshake-lru` (`auto`, `percpu` or `common`;
  default `auto`) selects the LRU layout of the scrub `scrub_handshakes(_v6)`
  maps. Invalid values are rejected at start-up.
  - `auto`: per-CPU LRU lists sized at load time so each online CPU keeps
    1/n of 500k entries per family; the map gets that share times the
    possible CPUs (the kernel splits per-CPU LRU maps over every possible
    CPU), capped at 1M entries per family. When that is not enough (more than
    twice as many possible as online CPUs) it falls back to one common LRU
    list with 500k entries.
  - `percpu`: always per-CPU lists, at most 1M entries per family, rounded
    down to a multiple of the possible CPUs.
  - `common`: one shared LRU list with 500k entries per family, the same
    memory as the previous release.
- Memory: the pair preallocates about 234 bytes per entry, about 111 MiB at
  500k entries and up to 223 MiB at 1M. With `auto` or `percpu`, hosts with
  more possible than online CPUs (CPU hotplug headroom, typical of VMs) use
  up to twice the previous memory; use `-scrub-handshake-lru common` to keep
  it at 500k entries. The collector logs the chosen mode, entries, per-CPU
  share and estimated memory at start-up ("Scrub handshake maps sized"), and
  warns when it cannot count the online CPUs (it then sizes for all possible
  CPUs).
- Fingerprint drain falls back to iterate-then-delete on kernels without batch
  map ops (before Linux 5.6). Entries read before an iteration error are
  deleted and reported; the rest of the map is drained before XDP writes to it
  again. New counter `packetyeeter_scrub_fingerprint_drain_errors_total`.
- Fingerprint overflow latch: once an insert fails because the active map is
  full, or its bucket lock timed out or detected a deadlock, that CPU stops
  inserting new buckets until the next generation (existing buckets keep
  counting and dropped packets count in
  `packetyeeter_scrub_fingerprint_overflow_total`). A lost bucket-lock trylock
  (`-EBUSY`) is retried on the next packet.

## 2026-10-04 - SYN cookie challenge rate cap

- New collector flag `-scrub-syn-cookie-max-pps` (default `0`, unlimited)
  caps the SYN cookie challenges a scrub node sends per second across all
  CPUs (one shared, paced budget), so challenge egress towards spoofed sources
  is bounded (cloud egress cost, provider packet-rate limits). Unverified SYNs
  over the cap are dropped unanswered and counted as
  `packetyeeter_scrub_syncookie_total{event="suppressed"}`; in `-dry-run` they
  are counted the same way and forwarded. See
  `docs/operations.md#syn-cookies`.

## 2026-10-03 - Scrub-mode SYN cookies

- New collector flag `-scrub-syn-cookies` (`off` by default, `auto`, `on`;
  scrub mode only, Linux 6.0+, refused with an error on older kernels). While
  active, `xdp_scrub` answers SYNs from sources it has not verified with a
  SYN-ACK carrying a SYN cookie instead of forwarding them, so spoofed-source
  SYN floods no longer reach the protected server. A client's answer verifies
  its source for `-scrub-syn-cookie-ttl` (default `10m`) and its next SYN is
  forwarded as before.
- `-scrub-syn-cookie-style oos` (default) sends an out-of-sequence SYN-ACK:
  the client answers with a RST and retransmits its SYN, so applications only
  see a slower first connect (a few ms on Linux, about 1 s on macOS/Windows).
  `reset` sends a valid SYN-ACK and resets the resulting connection, which
  applications see as one failed connect.
- `auto` challenges a destination while it receives more than
  `-scrub-syn-cookie-syn-pps` (default 10000) SYNs per second, for at least
  30 s. `-dry-run` only counts would-be challenges.
- New metrics `packetyeeter_scrub_syncookie_total{family,event}` and
  `packetyeeter_scrub_syncookie_verified_sources{family}`. Challenged SYNs
  count as `packetyeeter_scrub_packets_total{verdict="drop"}`.
- With the flag off the verifier removes the new code and its maps shrink to
  one entry. See `docs/operations.md#syn-cookies`.

## 2026-10-02 - Collector map polling performance

- The collector reads its eBPF maps with batch lookups (Linux 5.6+), falling
  back to per-key iteration on older kernels (logged once). One poll of a full
  3M-entry `icmp_rates` map drops from ~3.0 s to ~0.38 s, and walks no longer
  abort under flood churn. Map walk errors are now logged instead of ignored.
- Rate-map shadow state keeps only sources at or above the flood threshold, so
  spoofed-source floods no longer grow it to millions of entries. Signals are
  unchanged.
- Expired pending handshakes are consumed with batch deletes.
## 2026-10-02 - Optional TLS and mTLS for the analyzer gRPC API (SCR-20)

- Analyzer `-tls-cert`/`-tls-key` enable TLS on the gRPC listener;
  `-tls-client-ca` additionally requires client certificates signed by that CA.
- Collector `-analyzer-tls-ca` enables TLS and verifies the analyzer;
  `-analyzer-tls-cert`/`-analyzer-tls-key` present a client certificate;
  `-analyzer-tls-server-name` overrides the verified name.
- Analyzer `-control-client-names` limits `PushRules` and `WatchDecisions` to
  the named client certificates (`PermissionDenied` otherwise).
- Certificates, keys and CA bundles are reloaded on change without a restart;
  a bad file keeps the previous material and is logged.
- All off by default: plaintext deployments are unchanged. Inconsistent flag
  combinations and unreadable files fail at startup. The analyzer now logs a
  warning at startup when the listener is plaintext. See
  `docs/operations.md#tls-and-mtls`.
## 2026-10-02 - XDP hot-path performance

- Fix: dropping a packet from an IPv4 `blocked_ips` source no longer adds 1 to
  the entry's value. That value is the block's start time, so every drop
  pushed expiry back by 1 ns (about 1 ms per million drops) and `yeetctl`
  showed a TTL that grew under attack. IPv4 blocks now expire on time, as IPv6
  blocks already did; dropping blocked IPv4 sources from several CPUs is also
  much cheaper.
- A repeat of the same bad TCP flag scan refreshes `last_seen` on the existing
  `bad_flags`/`bad_flags_v6` entry in place instead of re-inserting it per
  packet; a different scan from the same source still replaces the whole
  entry. Contents and alerting are unchanged.
- `tc_ingress_syn_monitor` checks the per-CPU event budget before building a
  JA4T event, so SYNs past the budget skip the event work. Handshake tracking
  still runs for every SYN.
- No verdict changes; enforcement and telemetry are unaffected.
## 2026-10-02 - Analyzer hot-path performance

- Rate-limit and block-dedup tracking sweep expired entries at most once per
  second instead of on every call; a 40k-unique-IP enforce-mode flood replay
  drops from ~37-51 s to ~25 ms. Dedup TTL semantics are unchanged.
- `packetyeeter_rate_limit_currently_blocked_{ips,asns}` now saturate at
  100,000 and may lag expiry by up to 1 s.
- Disabled Debug logs on the signal path no longer build fields or format
  IPs (SYN `processSignal` ~1.3 us/13 allocs to ~0.14 us/1 alloc).
- Over-cap map eviction uses selection instead of a full sort (~22 ms to
  ~2.5 ms per eviction at a 100k cap), evicting the same entries.
- `Analyzer.Close` is idempotent.
## 2026-10-02 - Faster scrub rule matching

- Port ranges are merged and sorted when a rule is installed, and IPv4 source
  prefixes are sorted with their span recorded, so XDP binary-searches them
  and rejects most packets on the source span. With 4096 rules and 32 covering
  one destination, the veth bench's worst case improves from -53% to -28%
  forwarding (see `docs/scrub-throughput.md`). No change to which packets
  match.

## 2026-10-02 - Asynchronous bot verification

- Crawler DNS verification no longer runs on the collector's signal stream.
  Previously each new IP with a crawler User-Agent behind an unresponsive PTR
  server stalled that collector's signal processing for 5 seconds. Lookups now
  run on a bounded worker pool with per-IP de-duplication; a full queue drops
  the lookup instead of waiting.
- Detection change: until an IP's verification completes (at most the
  5-second DNS budget), its requests are unverified - no verified-bot
  exemption, no impersonation penalty, and the browser-claim header heuristics
  are skipped. Requests after completion get the cached verdict as before.
  Dropped lookups, and lookups still pending past the DNS budget, are treated
  as plain unverified requests. See `docs/operations.md#bot-verification`.
- New metrics `packetyeeter_bot_verification_queue_depth`,
  `packetyeeter_bot_verification_queue_drops_total{reason}` and
  `packetyeeter_bot_verification_pending_total{bot_type}`.
## 2026-10-02 - Analyzer decision stream

- New `WatchDecisions` gRPC stream for a scrub controller: every command sent
  to collectors (once per decision, only if actually sent), campaign
  observations and scrub fingerprints. Off by default behind
  `-enable-watch-api`; `-watch-max-subscribers` (16) and `-watch-buffer-size`
  (10000, drop-oldest) bound it. See
  `docs/operations.md#decision-stream-for-controllers`.
- `SIGNAL_SCRUB_FINGERPRINT` is validated and passed through, never scored.
- New metrics `packetyeeter_watch_subscribers`,
  `packetyeeter_watch_published_total{kind}`,
  `packetyeeter_watch_dropped_total` and
  `packetyeeter_watch_invalid_fingerprints_total`.

## 2026-10-02 - Scrub mode throughput procedure and loop test

- `docs/scrub-throughput.md`: how to measure a scrub node on real hardware
  (TRex or pktgen), what to read, and veth lab reference numbers.
- `make bench-scrub-veth` (`scripts/xdp_scrub_bench.sh`): informational veth
  benchmark for forwarding with and without 4096 rules and under a spoofed
  SYN flood.
- `make e2e-scrub-test` now also checks that a routing loop shows up in
  `packetyeeter_scrub_ttl_expired_total` and that `-dry-run` forwards traffic a
  DROP rule matches while still counting the match.
## 2026-10-02 - Scrub mode fingerprints

- `xdp_scrub` counts packets and bytes per destination, protocol, destination
  port, size bucket, TTL bucket, source /24 or /48 and verdict in two
  alternating per-CPU maps (65,536 buckets each). Every
  `-fingerprint-interval` (default `10s`, `0` = off) the collector sends the
  busiest `-fingerprint-top` (default 32) buckets of up to 256 destinations as
  `SIGNAL_SCRUB_FINGERPRINT`, without an IP so current analyzers ignore them.
  See `docs/operations.md#fingerprints`.
- New metrics `packetyeeter_scrub_fingerprint_buckets`,
  `packetyeeter_scrub_fingerprint_overflow_total` and
  `packetyeeter_scrub_fingerprint_capped_total{kind}`.
- The collector warns in host mode about non-default fingerprint flags.

## 2026-10-02 - Analyzer PushRules for scrub collectors

- New `PushRules(RuleSet)` RPC: a controller sets the complete rule set of its
  scope, and the analyzer sends every scrub collector the complete set of all
  scopes as a replacement (`RuleSetDelta.replace`) on each push, on
  (re)connect and once a minute, so collectors converge without
  acknowledgements. Off unless the analyzer runs with
  `-enable-rule-api`, since the gRPC listener is unauthenticated unless mTLS
  (`-tls-client-ca`) is configured.
- Optional `-rule-state-dir`: the analyzer persists pushed rules and restores
  them on start, so a restart does not clear scrub collectors' rules until the
  controller pushes again.
- Collectors announce `role=host|scrub` (and their hostname) when they connect;
  the analyzer does not score that announcement, and older analyzers drop it
  because it carries no IP.
- All scopes together must encode to at most 3 MiB, rules are withdrawn 5
  seconds before they expire, and `PushRules` waits at most 10 seconds for
  collector sends.
- With `-dry-run` or the kill switch pulled, only `PASS` rules are sent;
  pulling the kill switch withdraws existing `DROP`/`RATE_LIMIT` rules.
- New analyzer metrics `packetyeeter_rules_desired{scope}` and
  `packetyeeter_rule_deltas_sent_total`.

## 2026-10-02 - Scrub mode handshake map per-CPU LRU

- `xdp_scrub` tracks handshakes in its own `scrub_handshakes(_v6)` maps, LRU
  hashes with per-CPU LRU lists (`BPF_F_NO_COMMON_LRU`), instead of sharing
  `pending_handshakes(_v6)` with host mode. A random-source SYN flood no longer
  contends on one LRU lock across CPUs. Host mode is unchanged, and each mode
  only creates its own pair of maps.
- The 500k-entry capacity is now split evenly across the kernel's possible
  CPUs for eviction, so under a flood hitting few RX queues, or on a host with
  far fewer online than possible CPUs, old entries are evicted earlier.
  Superseded on 2026-10-04: the maps are now sized for the online CPUs and
  the layout is selectable with `-scrub-handshake-lru` (see "Scrub handshake
  maps sized for online CPUs" above).

## 2026-10-02 - Scrub mode handshake tracking fixes

- An ACK the kernel forwards (slow path, e.g. right after a neighbour
  expired) now completes a tracked handshake too, so such clients are no longer
  reported as incomplete handshakes.
- An RST|ACK no longer counts as completing a handshake.

## 2026-10-02 - Scrub mode runtime rules

- Scrub collectors apply match rules delivered as `COMMAND_SET_RULES`
  (`Rule`, `RuleSetDelta` and `RuleAction` added to the proto). Rules match on
  destination prefix, protocols, ports, length, TCP flags, fragment state and
  source prefixes, and `DROP`, `RATE_LIMIT` or `PASS` matching traffic in XDP.
  Deltas apply all-or-nothing; rules expire on `expires_at`. See
  `docs/operations.md#runtime-rules`.
- New metrics `packetyeeter_scrub_rule_matches_total{action}` and
  `packetyeeter_scrub_rules_active{family}`; new incident reason `rule_match`.
- The analyzer does not send rules yet; `PushRules` follows separately.

## 2026-10-02 - Scrub mode handshake tracking

- `xdp_scrub` tracks TCP handshakes for forwarded traffic: a SYN opens an entry
  and the client's first ACK closes it, since the SYN-ACK never crosses a scrub
  node. Unanswered SYNs reach the analyzer as `SIGNAL_INCOMPLETE_HANDSHAKE`,
  exactly as in host mode. Handshake RTT (JA4L) is not available in scrub mode.
- New `-handshake-timeout` (default `3s`, the previous hard-coded value) sets
  how long a SYN may stay unanswered before it is reported, in both modes.

## 2026-10-02 - Scrub mode review fixes

- IPv6 forwarding is now required whenever IPv6 can be routed out of the inside
  port (including routes via link-local next hops), not only when a port has a
  global IPv6 address; the outside port's own `forwarding` sysctls are checked
  too. Applies to start-up and `/readyz`.
- Packets the kernel will not forward are counted as
  `packetyeeter_scrub_slow_path_total{reason="not_fwded"}` instead of
  `verdict="local"`, so a blackhole is visible.
- `blocked_ips` and `-policy` now apply to unicast traffic for the scrub node's
  own addresses (multicast, link-local, ARP and neighbour discovery still pass
  unchecked).
- New `-scrub-slow-path-pps` (default 100000, 0 = unlimited) caps packets handed
  to the kernel; over-limit packets are dropped and counted in
  `packetyeeter_scrub_slow_path_limited_total`.
- `local_addrs` holds 4096 addresses per family (was 256); poll-time sync
  failures are logged once per change.
- On shutdown the control plane keeps running during `-readyz-drain`, and
  `xdp_scrub` detaches before `xdp_pass_inside`.
- Failed redirects are counted as `drop` instead of `forward`.
- Host mode now rejects `-inside-if` and `-allow-generic`, and warns about a
  non-default `-readyz-drain` or `-scrub-slow-path-pps`.

## 2026-10-02 - Collector scrub mode

- New `-mode scrub` runs the collector as an inline scrubber: `xdp_scrub` on
  the outside port (`-i`) applies the existing per-source checks and forwards
  clean traffic out of `-inside-if` with `bpf_fib_lookup` and XDP redirect,
  handing anything it cannot forward to the kernel. Requires Linux 5.15+,
  native XDP (`-allow-generic` for labs), IP forwarding and non-strict
  `rp_filter`; see `docs/operations.md#scrub-mode`.
- Scrub nodes expose `/readyz` on the metrics listener, drain for
  `-readyz-drain` on shutdown, and export `packetyeeter_scrub_*` metrics.
- New `-xdp-mode` (`auto`, `native`, `generic`); `auto` keeps the previous
  host-mode behaviour.
- Host mode now writes monitor mode, allowlist and policy maps before attaching
  XDP rather than just after, so the first packets are already judged with the
  configured settings.

## 2026-08-09 - Collector UDP fragment policy and edge-triggered incidents

- Fragmented UDP / IPv6 Fragment headers no longer hard-drop by default.
  Default `-udp-frag-mode=rate` applies the normal UDP rate limit instead.
  Operators can restore the legacy hard-drop with `-udp-frag-mode=drop`.
- Kernel ICMP/UDP rate-limit incident emits are edge-triggered once per source
  per 1s window (`incident_emitted` in the rate map value) so a single over-limit
  flood cannot monopolize the per-CPU incident budget.

## 2026-08-09 - Operator reputation score caps

- Analyzer applies finite default reputation score caps so penalty mass cannot
  run away indefinitely while still leaving headroom above
  `-reputation-threshold`: IP/JA4 `200`, ASN `500`. Set
  `-reputation-ip-score-cap` / `-reputation-ja4-score-cap` /
  `-reputation-asn-score-cap` to `0` for uncapped. The reputation package API
  still defaults to uncapped when caps are not configured.

## 2026-08-09 - Statistical model weight calibration

- Built-in statistical fallback weights used by `Predict` now sum to `1.0`
  (rate/diversity mass is folded into the signal score). Missing JA4H is only
  treated as bot-like when HTTP context is present. Direct reputation-gate
  feature extraction sets wall-clock `TimeOfDay`/`DayOfWeek` instead of leaving
  them at zero. This is wiring/calibration only — no new labeled-data
  thresholds were invented.

## 2026-08-09 - Reduce JA4 and campaign false positives

- Coarse JA4DB wildcard matches and unclassified catalog entries remain
  enrichment-only instead of being emitted as high-severity known-bot signals.
  Detection signals now require an exact known-bot classification. Exact
  browser matches still reward reputation and short-circuit bot detection
  without emitting a bot signal. `IsKnownBot`/`GetInfo`/`CategorizeBot` and the
  JA4H lookup RPC now honor exact-vs-wildcard match types consistently.
- Observe-only campaign detections no longer mutate the reputation of an
  arbitrary representative source or ASN.
- `packetyeeter_active_attack_campaigns` now counts campaigns that meet
  detection criteria instead of all retained aggregation buckets.

## 2026-08-09 - Honor optional ML enforcement configuration

**Problem**: The direct reputation-block path always constructed a separate,
untrained statistical `ModelManager`, even when `-ml-model` was unset. That
made an unconfigured model veto reputation blocks. When `-ml-model` was set,
the configured ONNX model was loaded only into the AI engine; the separate
reputation gate still used the statistical model, and its model watcher could
not reload the ONNX model it did not own.

**Solution**:
- Without `-ml-model`, reputation-threshold blocks are no longer ML-gated.
- With `-ml-model`, one validated `HybridModel` is shared by the AI engine and
  reputation gate. A configured model that cannot load now fails analyzer
  startup instead of silently substituting an untrained heuristic.
- Model reloads update that shared model, and shutdown releases its ONNX
  resources.
- The reputation gate uses the resolved `-ai-confidence-threshold`, including
  the documented 0.7 default, and treats equality as meeting the threshold.
- Per-request model decisions are debug-level; the
  `packetyeeter_ml_blocks_overridden_total` counter remains the aggregate
  signal.
- The statistical fallback no longer treats a pristine raw reputation score
  as suspicious. Reputation is already blended separately against the
  configured ban threshold by the detection engine.

The built-in statistical model's scoring was deliberately left unchanged:
changing enforcement calibration requires representative labeled traffic, not
synthetic maximum-score tests.

## 2026-08-09 - Bound default metric cardinality

Exact ASN/organization metric families are now gated by
`-enable-high-cardinality-metrics`, matching the existing per-IP and
fingerprint metrics. They previously emitted thousands of persistent series
even with the flag disabled because organization names are free-text labels and
every observed ASN created multiple series. Aggregate counters and histograms
remain enabled by default.

## 2026-08-09 - Surface perf-ring telemetry loss

Collector perf readers now count and warn on kernel-reported lost samples via
`packetyeeter_perf_lost_samples_total{reader="tcp_metadata|incidents"}`.
Previously `perf.Record.LostSamples` was ignored, making overload look like a
clean absence of detections.

## 2026-08-09 - Grafana dashboard refresh

### Bring the checked-in dashboards back in sync with `pkg/metrics`
**Problem**: The dashboards had drifted from the code. Three panel targets
queried measurements that no longer exist (`packetyeeter_baseline_anomalies`,
`packetyeeter_baseline_stats`, `packetyeeter_ml_stats`) and rendered as empty
panels, and 57 of the registered metrics were not graphed anywhere. That
included the entire sustained-download subsystem, the enforcement kill-switch,
and every queue depth/drop gauge -- exactly the series an operator needs during
a staged rollout to tell "detection is quiet" apart from "detection is not
running".

**Solution**: Fixed the three stale targets and added rows covering the
remaining metrics: sustained download, enforcement safety, pipeline
backpressure, attack campaigns and carpet bombing, clock skew and payload
entropy, ML/AI engine health, and protocol/SPOE/reputation. Both dashboards now
cover every metric registered in `pkg/metrics` plus the reputation gauges.

**Privacy**: unchanged. Panels backed by per-IP, per-JA4H, or per-user-agent
series aggregate those labels away -- the per-IP detection counter is summed
inside a subquery so the address never reaches the panel, and `threat_intel_info`
and `ai_recent_detections` are reduced to series counts. Those panels stay empty
unless the analyzer runs with `-enable-high-cardinality-metrics`.

Also repacked `gridPos` in both files. The main dashboard had 18 overlapping
panel rectangles and the overview had 2, which Grafana silently reflowed on
import, so the checked-in layout did not match what operators actually saw.
Panels now carry unique ids.

## 2026-08-09 - Sustained-download detection

### Detect slow, patient bulk scrapers
**Problem**: Detection selected on rate. A client that pulls a very large
volume slowly, spread across many resources over a long window, never makes
any individual interval look abusive, so nothing fired. Rate thresholds low
enough to catch it would blanket legitimate traffic.
**Solution**: A new detector selects on duration and breadth instead. Two
independent signals are AND-ed: transferred volume, from a new eBPF TC-egress
per-client byte counter, and request breadth/shape (resource and section
fan-out) observed through the existing SPOE agent.

HAProxy cannot supply the byte half of this without stick tables: `bytes_out`
is per-stream and zeroed by `stream_new`, and keep-alive allocates a new stream
per request, so it never accumulates. `res.body_size` reports only the
advertised `Content-Length`, which is meaningless for streamed responses, and
was deliberately not used as a fallback rather than introduce a second,
inconsistent byte source. eBPF egress accounting is the only correct source.

Raw paths and hostnames are never retained -- resources and sections are
identified by FNV-64a hashes with a separator, so `("ab","c")` and `("a","bc")`
do not collide.

**Enforcement impact**: ships disabled, and enabling detection does not enable
blocking. `-sustained-enabled` reports only; `-sustained-enforce` is a separate
opt-in. The collector side is likewise off by default behind
`-egress-accounting`. Reputation raises the request and byte floors but never
the resource/section floors, release from a hold is judged on requests and
breadth rather than bytes (blocking destroys the byte evidence), and the hard
hold ceiling bounds the cost of a false positive. Allowlisted addresses are
skipped entirely. Stage it with `-dry-run` and tune against the margins
reported by `/api/sustained`.

### Analyzer-wide runtime enforcement kill switch
`POST /api/enforcement/stop` halts every enforcing command while detection and
reporting continue. It sits at the command-issuing boundary rather than inside
any one detector, so it covers all of them, and is checked before the dedup
reservation -- otherwise a suppressed block would mark the address "recently
blocked" and stay suppressed for the dedup TTL after enforcement resumed.
One-way by design: resuming requires a config change and a restart.

### Removed: HAProxy peer (stick-table) listener
Dead code. It blocked on any stick-table update with no volume logic and was
never wired to anything.

### BREAKING: `-haproxy-port` removed
The flag backed the listener above. Go's flag parser rejects unknown flags, so
a collector still passing it exits with status 2, and `Restart=on-failure`
turns that into a crash loop rather than a clean failure. The package ships a
corrected unit, but a local systemd drop-in overriding `ExecStart=` shadows it
and survives the upgrade, so check the resolved configuration before upgrading:

```bash
systemctl cat packetyeeter-collector | grep -n haproxy-port   # expect no output
```

`collector-postinstall.sh` performs the same check and names any file still
passing the flag. It warns rather than editing, since the package cannot safely
rewrite operator-authored drop-ins.

Validated on Linux 6.8 against live traffic: eBPF loaded and attached, egress
maps populated per client, signals reached the analyzer attributed to the
correct address, the byte floor gated as designed, and the kill switch flipped
both `/api/enforcement` and `packetyeeter_enforcement_stopped`. An older
analyzer tolerates the new `SIGNAL_EGRESS_VOLUME` without erroring, so a
collector-first rollout is safe.

## 2026-07-17 - IPv6 flood detection parity

### Collector: report IPv6 ICMP/UDP floods
**Problem**: The XDP program tracked IPv6 ICMP and UDP floods into the
`icmp_rates_v6` / `udp_rates_v6` maps, but userspace only ever read the IPv4
maps. On a dual-stack host, IPv6 floods were counted and rate-limited in the
kernel but never turned into analyzer signals, so reputation/blocking never
saw them.
**Solution**: `sendICMPRates`/`sendUDPRates` now also drain the v6 maps
(same 1000-pps threshold, same allowlist and dry-run gating as v4) and emit
`SIGNAL_ICMP_FLOOD` / `SIGNAL_UDP_FLOOD` for IPv6 sources. Also normalized the
IPv6 incomplete-handshake weight to the v4 formula (pps, clamped to 50000)
instead of a raw per-poll count, and set the previously-unused
`packetyeeter_udp_total_rate_pps` gauge.

**Enforcement impact**: dual-stack collectors will now generate IPv6
flood/handshake signals that can drive blocks. Stage the rollout with analyzer
`-dry-run` and confirm IPv6 detections look right before enforcing, the same as
any threshold change. IPv4-only deployments are unaffected.

Validated end-to-end on a virtual veth pair (see
`scripts/xdp_veth_test.sh`): before, an IPv6 flood produced 0 analyzer
signals; after, the same flood produced IPv6 `SIGNAL_ICMP_FLOOD`/
`SIGNAL_UDP_FLOOD` at the analyzer while IPv4 behavior was unchanged.

## 2026-07-17 - Reputation per-IP / per-JA4 penalties activated

**Fix**: The reputation engine's per-IP and per-JA4 score caps defaulted to 0,
which clamped every IP and JA4 penalty back to 0 inside `penalizeLocked`. As a
result all per-IP and per-JA4 reputation scoring was a silent no-op (only ASN
scoring, whose cap defaulted to +Inf, accumulated). The caps now default to
+Inf (uncapped), matching ASN, so IP/JA4 penalties accumulate and can reach the
ban threshold.

**Enforcement impact**: this re-activates per-IP and per-JA4 reputation
accumulation that was previously dormant. Sources that repeatedly trip
detections will now accrue score and can cross `WouldBlock`/ban thresholds where
before they never did. Stage it: run the analyzer with `-dry-run`, watch
`packetyeeter_*_blocks_total`, reputation scores, and AI detections, and tune
allowlists/thresholds before disabling dry-run. Operators who want a ceiling can
set one explicitly via the score-cap setters.

## 2026-01-21 - Major Updates

### 1. YeetExplorer Pagination Fix
**Problem**: yeetexplorer was hanging with too many entities in memory
**Solution**: Implemented pagination system
- Page size: 100 entities per page
- Navigate with `←` (previous) and `→` (next) arrow keys
- Dynamic title showing: "Page X/Y [start-end of total]"
- Filter still works across all entities
- Fixes memory issues and UI responsiveness

### 2. Grafana Dashboard - Bot Detection Metrics
**Added New Section**: "Bot Detection & AI Crawlers" row with 5 new panels:

#### Panel 1: Bot Detections by Category (Donut Chart)
- Metric: `packetyeeter_ai_detections_by_category_total`
- Shows distribution across 13 categories:
  - ai_crawler_verified, ai_crawler_unknown
  - search_engine, search_unknown
  - monitoring, scanner, script
  - scraper, ddos, legitimate, malicious, unknown

#### Panel 2: Bot Detection Rate by Category (Stacked Bars)
- Rate per second by category
- Helps identify attack patterns in real-time

#### Panel 3: Bot Verification Results (Pie Chart)
- Metric: `packetyeeter_ai_verification_results_total`
- Shows verification status distribution:
  - verified, failed, skipped, unknown
- Indicates DNS verification success rate

#### Panel 4: Behavioral Patterns Detected (Line Chart)
- Metric: `packetyeeter_ai_behavioral_patterns_total`
- Tracks detected patterns:
  - persistent (long-lived activity)
  - high_frequency (rapid requests)
  - bursty (traffic spikes)

#### Panel 5: Bot Detection Confidence Score (Histogram)
- Metric: `packetyeeter_ai_confidence_by_category`
- Confidence distribution per category (0-100%)
- Color-coded: green (<50%), yellow (50-70%), red (>70%)

### 3. JA4 Database Integration
**New Feature**: Periodic JA4 fingerprint database downloads from ja4db.com

#### Component: pkg/ja4db/downloader.go
- **Download Interval**: Every 12 hours
- **Cache Path**: `/var/cache/packetyeeter/ja4db.json` (configurable)
- **Database Size**: Thousands of known JA4 fingerprints
- **Verification**: Identifies known bots, crawlers, scanners

#### Features:
- **Automatic Updates**: Downloads fresh database every 12 hours
- **Persistent Cache**: Survives restarts, loads immediately on boot
- **Fast Lookup**: O(1) fingerprint verification via map
- **Thread-Safe**: RWMutex protection for concurrent access
- **Graceful Degradation**: Continues operation if download fails

#### Methods:
```go
IsKnownBot(fingerprint string) bool
GetInfo(fingerprint string) string  // Returns app name, library, device
Lookup(fingerprint string) (interface{}, bool)
Stats() map[string]interface{}
```

#### Integration:
- **pkg/fingerprint/analyzer.go**: Added JA4Verifier interface
- **pkg/protector/service.go**: Initializes downloader on startup
- **Global Access**: `fingerprint.GetJA4Info(fp)` available everywhere

#### Configuration Flags (main.go):
```bash
-ja4db-cache string
    Path to JA4 database cache file (default "/var/cache/packetyeeter/ja4db.json")
-disable-ja4db
    Disable JA4 database downloads
```

#### Example Usage:
```go
// In any detection logic
isKnown, info := fingerprint.GetJA4Info(ja4Hash)
if isKnown {
    log.WithField("info", info).Warn("Known bot detected")
    // info: "Chrome 120.0 (BoringSSL) on Windows [verified]"
}
```

#### Database Format (JA4Entry):
```json
{
  "fingerprint": "t13d1516h2_8baaf6152771_02c76c77241c",
  "application": "Chrome",
  "library": "BoringSSL",
  "device": "Windows",
  "os": "Windows 11",
  "user_agent": ["Mozilla/5.0..."],
  "verified": true,
  "notes": "Official Google Chrome build"
}
```

#### Metrics Impact:
- Can now correlate JA4 fingerprints with known applications
- Reduces false positives by identifying legitimate clients
- Enhances bot categorization accuracy
- Provides context for alerts (e.g., "GPTBot [verified]")

#### Error Handling:
- Failed downloads logged as warnings (not fatal)
- Continues with cached data if network unavailable
- Automatic retry on next 12-hour interval
- Invalid JSON gracefully skipped

### Summary of Changes
**Files Modified**: 7
**New Files Created**: 1
**New Metrics**: 4 (already existed, now visualized in dashboard)
**New Config Flags**: 2
**Performance Impact**: 
  - yeetexplorer: Memory usage reduced by 80% with large datasets
  - JA4DB: ~2MB cache file, 60s initial download, negligible CPU

### Deployment
```bash
./deploy.sh webfrontend01.example.com
```

### Next Steps
1. Monitor JA4 database download logs
2. Verify Grafana dashboard panels populate
3. Test yeetexplorer pagination with 1000+ entities
4. Consider allowlisting verified legitimate crawlers
5. Add JA4 info to yeetexplorer detail view (future enhancement)

### Compatibility
- Backward compatible (all new features optional)
- Existing functionality unchanged
- Grafana dashboard v42 (updated from v42)
- Requires Go 1.19+ for ja4db package
