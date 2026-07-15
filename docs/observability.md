# Observability

PacketYeeter exposes Prometheus metrics from the collector and analyzer and emits
structured JSON logs for detection decisions. Modern DDoS campaign metrics are
analyzer-side observations: they summarize aggregate behavior for operators, but
do not send block commands by themselves.

## Logging schema (JSON)

Standard fields:

- `component`: `aidetection_engine`, `analyzer`, `collector`, `spoe_agent`, `ebpf`
- `event`: `ai_detection`, `block_command`, `rate_limit`, `threat_enrich`, `ja4db_hit`, `ml_override`, `attack_campaign_observed`
- `ip`, `dest_ip`, `dst_port`, `asn`, `ja4h`
- `confidence`, `ml_confidence`, `ml_category`, `ml_is_bot`
- `bot_category`, `verification`
- `reason`, `duration_secs`
- `signal_count`, `signal_breakdown`, `source_breakdown`
- optional: `collector_id`, `command_id`, `detection_id`, `campaign_id`

Campaign observation logs include low-cardinality aggregate fields such as
`vector`, `reason`, `dest_ips`, `dest_subnets`, `dest_ports`, `source_ips`,
`total_weight`, and `observe_only=true`. Baseline metadata may include
`baseline_service_key`, `baseline_protocol`, `baseline_dst_port_bucket`,
`baseline_current_rate`, `baseline_rate`, `baseline_effective_rate`,
`baseline_multiplier`, `baseline_samples`, `baseline_enough_samples`, and
`baseline_anomalous`.

## Metric catalog

### DDoS campaign metrics

| Metric | Type | Labels | Meaning |
| :--- | :--- | :--- | :--- |
| `packetyeeter_attack_campaign_detections_total` | counter | `vector`, `reason` | Aggregate attack campaigns observed by the analyzer. |
| `packetyeeter_active_attack_campaigns` | gauge | none | Active campaign keys in the current analyzer aggregation window. |
| `packetyeeter_carpet_bombing_detections_total` | counter | `vector`, `reason` | Campaigns broad enough across destinations, subnets, ports, or sources to be treated as carpet-bombing observations. |
| `packetyeeter_campaign_baseline_multiplier` | histogram | `vector`, `protocol`, `dst_port_bucket`, `enough_samples` | Observed campaign signal rate divided by the adaptive EWMA service baseline. |
| `packetyeeter_campaign_baseline_rate` | gauge | `vector`, `protocol`, `dst_port_bucket`, `enough_samples` | Adaptive EWMA campaign signal baseline rate for a service key. |

Known low-cardinality UDP and DDoS vectors are `dns_reflection`,
`ntp_reflection`, `ssdp_reflection`, `cldap_reflection`,
`memcached_reflection`, `quic_initial_flood`, `udp_flood`, `syn_flood`,
`icmp_flood`, and `bad_flags`. The fallback `udp_flood` means the analyzer did
not have enough port/protocol metadata to classify a more specific UDP vector.

Campaign reasons are intentionally aggregate and bounded, for example
destination breadth, destination subnet breadth, destination port breadth,
source breadth, and total campaign weight. Do not add per-IP, per-subnet, JA4,
or user-agent labels to shared dashboards or default alerting.

Internally, the analyzer groups signals into a specific-subnet campaign
(vector/source/collector/destination-subnet) plus two low-cardinality
aggregate rollups: a per-collector cross-subnet rollup and a fully
cross-collector rollup. The cross-collector rollup exists so an attacker
that spreads traffic across many collectors (in addition to, or instead of,
many destination subnets) cannot evade aggregation by varying
`collector_id` alone. The weak-source-breadth ("many weak source IPs")
check runs independently of the destination-breadth checks and applies to
both the specific campaign and the aggregate rollups, so a combined
attack - many weak source IPs *and* many destination subnets/collectors,
each individually under its own threshold - is still caught. An aggregate
rollup only reports a detection when it captures breadth its narrower scope
does not already have (e.g. more than one destination subnet, or more than
one collector), so the same underlying signals are never double-counted
across the specific campaign and its aggregates.

Campaign/carpet-bombing detections feed the same reputation system as
regular (non-campaign) detections: their confidence is computed from the
campaign's own evidence (signal volume, destination/source breadth relative
to configured thresholds, source/collector/vector diversity, and adaptive
baseline anomaly) and blended with the ML model via `blendMLConfidence`
when one is configured, exactly like the non-campaign detection path -
there is no hardcoded confidence value. The resulting confidence also drives
a reputation penalty for the campaign's representative sample IP and ASN,
scaled by a bounded severity multiplier (how far the campaign exceeds its
breadth thresholds, capped at 5x). To avoid a per-source-IP hot loop under
carpet bombing (which can involve thousands of weak sources in a single
detection cycle), only the representative sample IP/ASN is penalized per
detection - not every contributing source IP - mirroring the single
`Penalize`/`PenalizeASN` calls used by the non-campaign path. This does not
change `WouldBlock` semantics: campaign detections remain observe-only
(`observe_only=true`, `enforcement_scope="none"`) exactly as before; only the
confidence/reputation *scoring* is now consistent with regular detections.

### Baseline rate-of-change guardrail

The adaptive per-service EWMA baseline (`CampaignBaselineConfig`) accepts a
`MaxGrowthPerObservation` cap (default `1.5`, i.e. at most a 50% increase per
observation) on how fast the learned baseline itself may rise. This mitigates
slow-ramp "baseline poisoning" attacks that increase traffic gradually
(e.g. ramping up every window while staying under the anomaly multiplier
relative to the *previous* baseline) in an attempt to drag the baseline up
to normalize the attack's own traffic. The cap only limits upward movement of
the baseline; it does not affect how quickly the baseline can fall back down,
and it does not change how a sudden spike against an already-established
baseline is detected (that comparison always uses the pre-update baseline).

**Known limitation**: the cap bounds how fast the baseline can move per
observation window, not in absolute time - a sustained legitimate traffic
increase can still take several observation cycles to be reflected in the
baseline, and a sufficiently slow multi-day ramp that stays within the
per-observation growth cap could still eventually poison the baseline. This
is a deliberate, simple mitigation (not a full changepoint/CUSUM detector);
operators with unusually fast-growing legitimate traffic should tune
`MaxGrowthPerObservation` (or set it to `1` to restore the pre-fix unbounded
behavior) alongside `Tau` and `AnomalyMultiplier`.

### Existing detection and enforcement metrics

- **Blocks and detections**: `packetyeeter_*_blocks_total`,
  `packetyeeter_*_detections_total`,
  `packetyeeter_tcp_syn_flood_blocks_total`,
  `packetyeeter_tcp_bad_flags_blocks_total`.
- **Rate limiting**: `packetyeeter_rate_limit_*`,
  `packetyeeter_rate_limit_currently_blocked_*`.
- **HTTP**: `packetyeeter_http_requests_per_second_by_*`,
  `packetyeeter_http_path_signals_total`,
  `packetyeeter_http_path_entropy_by_ip`.
- **SPOE**: `packetyeeter_spoe_queue_depth`,
  `packetyeeter_spoe_queue_drops_total`,
  `packetyeeter_spoe_anomaly_total`, `packetyeeter_proxy_lag_max_ms`.
- **ML/Bot/JA4DB**: `packetyeeter_ml_*`,
  `packetyeeter_bot_detections_by_category_total`,
  `packetyeeter_bot_verification_*`, `packetyeeter_ja4db_*`.
- **AI engine**: `packetyeeter_ai_signals_by_*`,
  `packetyeeter_ai_signal_ewma_by_*`,
  `packetyeeter_ai_state_entries`,
  `packetyeeter_ai_confidence_threshold`,
  `packetyeeter_ai_detections_action_total`,
  `packetyeeter_ai_detection_confidence_bucket`,
  `packetyeeter_ai_blocks_by_signal_total`.

`packetyeeter_ai_state_entries{component=...}` reports bounded in-memory state
for components such as behavioral profiles, EWMA baselines, event histories,
latest detections, and compact detection history. The `component` label is a
fixed low-cardinality set and is safe for default dashboards and alerts.
- **Entropy and patterns**: `packetyeeter_payload_entropy_*`,
  `packetyeeter_pattern_tracker_profiles`,
  `packetyeeter_pattern_detections_total`.
- **ASN baseline**: `packetyeeter_latency_ewma_by_asn_ms`,
  `packetyeeter_asn_*`.

## Query and panel guidance

- Counters: use `rate()` in Prometheus or
  `non_negative_derivative(max("counter"),1s)` in Influx.
- Gauges: use instant queries or `max()` over a short range. For top-k views,
  use `topk()` in Prometheus and grouped tables in Influx.
- Histograms: use `histogram_quantile()` over `rate(<metric>_bucket[5m])`.
- `enough_samples="false"` on `packetyeeter_campaign_baseline_multiplier` is
  warmup context, not attack evidence.
- The analyzer flag `--ai-confidence-threshold` (default `0.7`) controls AI
  blocking threshold and appears in log reasons.

Suggested campaign-level Grafana panels:

| Panel | PromQL |
| :--- | :--- |
| Campaign observations by vector | `sum by (vector) (rate(packetyeeter_attack_campaign_detections_total[5m]))` |
| Carpet-bombing observations by vector and reason | `sum by (vector, reason) (rate(packetyeeter_carpet_bombing_detections_total[5m]))` |
| Active campaigns | `packetyeeter_active_attack_campaigns` |
| Baseline multiplier p95 | `histogram_quantile(0.95, sum by (le, vector, protocol, dst_port_bucket, enough_samples) (rate(packetyeeter_campaign_baseline_multiplier_bucket[15m])))` |
| Baseline rate by service key | `packetyeeter_campaign_baseline_rate` |

The checked-in `grafana-dashboard.json` already contains broad protection, AI,
and baseline panels. The campaign panels above are intentionally documented as a
focused panel plan instead of expanding the dashboard JSON in this PR; they can
be added to local/private dashboards without introducing high-cardinality views.

## Alerts and scrape config

See `../examples/prometheus-scrape.yml` for a minimal Prometheus scrape config
and `../examples/prometheus-alerts.yml` for example campaign, carpet-bombing,
baseline, and queue-pressure alert rules. Tune alert thresholds against local
traffic before paging operators.

Metrics endpoints and the inspector are unauthenticated. Bind them to loopback
or trusted management networks, or protect them with firewall/VPN controls.
