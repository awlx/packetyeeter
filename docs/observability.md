# Observability

## Logging Schema (JSON)
Standard fields:
- `component`: aidetection_engine | analyzer | collector | spoe_agent | ebpf
- `event`: ai_detection | block_command | rate_limit | threat_enrich | ja4db_hit | ml_override
- `ip`, `asn`, `ja4h`
- `confidence`, `ml_confidence`, `ml_category`, `ml_is_bot`
- `bot_category`, `verification`
- `reason`, `duration_secs`
- `signal_count`, `signal_breakdown`, `source_breakdown`
- optional: `collector_id`, `command_id`, `detection_id`

## Metrics ↔ Panels

### Prometheus Dashboard (`grafana-dashboard.prom.json`)
- **Overview**: blocks/detections (`packetyeeter_*_blocks_total`, `*_detections_total`)
- **Rate Limiting**: `*_rate_limit_*`, `packetyeeter_rate_limit_currently_blocked_*`
- **HTTP**: `packetyeeter_http_requests_per_second_by_*`, `packetyeeter_http_path_signals_total`, `packetyeeter_http_path_entropy_by_ip`
- **SPOE**: `packetyeeter_spoe_queue_depth`, `_drops_total`, `packetyeeter_spoe_anomaly_total`, `packetyeeter_proxy_lag_max_ms`
- **ML/Bot**: `packetyeeter_ml_*`, `packetyeeter_bot_detections_by_category_total`, `packetyeeter_bot_verification_*`, `packetyeeter_ja4db_*`
- **AI Engine**: `packetyeeter_ai_signals_by_*`, `packetyeeter_ai_signal_ewma_by_*`
- **Entropy**: `packetyeeter_payload_entropy_*`
- **Pattern**: `packetyeeter_pattern_tracker_profiles`, `packetyeeter_pattern_detections_total`
- **ASN Baseline**: `packetyeeter_latency_ewma_by_asn_ms`, `packetyeeter_asn_*`

### Influx Dashboard (`grafana-dashboard.json`)
- Mirrors Prom panels using `SELECT non_negative_derivative(...)` for counters and `max("gauge")` for gauges.
- **Updated queries** use `packetyeeter_ai_signals_by_type_total` (not `*_ai_signals_total`).
- Additional panels: path entropy, payload entropy, pattern tracker, SPOE queue, AI EWMA, ASN latency, rate-limit currently blocked.
- **AI Decisions Explained**: `packetyeeter_ai_confidence_threshold`, `packetyeeter_ai_detections_action_total`, `packetyeeter_ai_detection_confidence_bucket`, `packetyeeter_ai_blocks_by_signal_total`.

## Notes
- Counters: use `rate()` (Prom) or `non_negative_derivative(max("counter"),1s)` (Influx).
- Gauges: use `max()`/instant queries; for top-k (Prom) use `topk`, for Influx use `GROUP BY` and tables.
- Analyzer flag: `--ai-confidence-threshold` (default `0.7`) controls AI blocking threshold and appears in log reasons.
- Metrics endpoints and the inspector are unauthenticated. Bind them to loopback
  or trusted management networks, or protect them with firewall/VPN controls.
- See `../examples/prometheus-scrape.yml` for a minimal Prometheus scrape config.
