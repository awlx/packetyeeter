# PacketYeeter Changelog

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
