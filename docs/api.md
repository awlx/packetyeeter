# PacketYeeter API Documentation

This document describes the HTTP API endpoints available in the PacketYeeter analyzer.

## Base URL

By default, the Inspector API listens on `127.0.0.1:9092`. This can be configured with the `--inspect-addr` flag.

**Security Note**: The Inspector API is intended for local/admin access only. Do not expose it publicly without proper authentication.

---

## Detection Inspection Endpoints

### GET /api/detections

Returns all recent detection events (last 1000).

**Response:**
```json
[
  {
    "ip": "203.0.113.42",
    "ja4": "t13d1516h2_8daaf6152771_b0da82dd1658",
    "ja4h": "ge11nn10_484d1729db89_443e0631dad3",
    "asn": "AS15169",
    "org": "Google LLC",
    "signal_count": 127,
    "detection_time": "2026-01-29T10:15:30Z",
    "ewma_baseline": 42.5,
    "confidence": 0.89,
    "ml_confidence": 0.85,
    "bot_category": "scraper",
    "verification_status": "unverified",
    "block_reason": "High scraper confidence (0.89) above threshold 0.70",
    "signal_breakdown": {
      "http_high_frequency": 45,
      "path_enumeration": 32,
      "missing_static_assets": 18,
      "bot_ua": 5
    },
    "source_breakdown": {
      "http": 95,
      "tcp": 32
    },
    "signals": [
      {
        "type": "bot_ua",
        "source": "http",
        "weight": 1.0,
        "timestamp": "2026-01-29T10:15:28Z",
        "metadata": {
          "user_agent": "Mozilla/5.0 (compatible; YandexBot/3.0)",
          "matched_pattern": "YandexBot"
        }
      },
      {
        "type": "path_enumeration",
        "source": "http",
        "weight": 1.0,
        "timestamp": "2026-01-29T10:15:29Z",
        "metadata": {
          "path": "/api/users/12345",
          "numeric_id": 12345,
          "previous_id": 12344
        }
      }
    ]
  }
]
```

**Signal Metadata:**
Each signal includes a `metadata` field with additional context:
- `bot_ua`: Contains `user_agent` (actual UA string) and `matched_pattern`
- `path_enumeration`: Contains `path`, `numeric_id`, sequence info
- `missing_static_assets`: Lists missing resources
- `ja4_mismatch`: Browser fingerprint details
- And more - inspect the metadata to see what caused the signal!

### GET /api/ip/{ip}

Get detailed information about a specific IP address.

**Example:** `GET /api/ip/203.0.113.42`

**Response:**
```json
{
  "detection": {
    "ip": "203.0.113.42",
    "signal_count": 127,
    "confidence": 0.89,
    "bot_category": "scraper",
    "block_reason": "High scraper confidence (0.89) above threshold 0.70"
  },
  "reputation": 65.5
}
```

If the IP has no detection event, the `detection` field will be `null`.

### GET /api/ja4h/{fingerprint}

Get detection information for a specific JA4H HTTP fingerprint.

**Example:** `GET /api/ja4h/ge11nn10_484d1729db89_443e0631dad3`

**Response:** Same format as detection object above, or `null` if not found.

---

## Feedback Loop Endpoints

### POST /api/feedback/report-fp

Report a false positive (incorrectly blocked legitimate traffic).

**Request Body:**
```json
{
  "ip": "203.0.113.42",
  "reason": "Legitimate user, aggressive behavior but not malicious",
  "labels": ["cdn", "monitoring_tool", "legitimate_crawler"]
}
```

**Fields:**
- `ip` (required): IP address to report
- `reason` (optional): Free-text explanation
- `labels` (optional): Array of labels for ML training. Suggested labels:
  - `legitimate_crawler` - Search engine or legitimate bot
  - `cdn` - CDN or edge node
  - `monitoring_tool` - Uptime monitor, synthetic test
  - `api_client` - Legitimate API consumer
  - `mobile_app` - Mobile app traffic
  - `aggressive_human` - Real user with aggressive patterns
  - `test_traffic` - Internal testing

**Response:**
```json
{
  "status": "ok",
  "message": "false positive recorded for 203.0.113.42",
  "labels": ["cdn", "monitoring_tool"]
}
```

**Effects:**
- IP is added to allowlist for 24 hours
- False positive counter incremented
- Threshold automatically adjusted if FP rate exceeds target
- **ML model is retrained**: The pattern is learned as legitimate traffic (label: human/not bot)
- Prometheus metric `packetyeeter_feedback_false_positives_total` incremented

**Pattern Learning:**
When you report a false positive, the ML model extracts the features from that detection (signal types, sources, behavioral patterns, etc.) and retrains with the correct label (human). This means:
- Future traffic with similar patterns is less likely to be flagged
- The model learns what legitimate traffic looks like in your environment
- Over time, the system becomes more accurate for your specific use case

**Example with curl:**
```bash
curl -X POST http://localhost:9092/api/feedback/report-fp \
  -H "Content-Type: application/json" \
  -d '{"ip":"203.0.113.42","reason":"Legitimate CDN","labels":["cdn"]}'
```

### POST /api/feedback/report-tp

Report a true positive (correctly identified bot/attack).

**Request Body:**
```json
{
  "ip": "198.51.100.99",
  "reason": "Confirmed scraper attack"
}
```

**Response:**
```json
{
  "status": "ok",
  "message": "true positive recorded for 198.51.100.99"
}
```

**Effects:**
- True positive counter incremented
- Threshold automatically adjusted if FP rate is below target
- **ML model is retrained**: The pattern is reinforced as malicious traffic (label: bot)
- Prometheus metric `packetyeeter_feedback_true_positives_total` incremented

**Pattern Learning:**
When you report a true positive, the ML model reinforces that this pattern is indeed malicious. This strengthens the model's ability to detect similar attacks in the future.

**Example with curl:**
```bash
curl -X POST http://localhost:9092/api/feedback/report-tp \
  -H "Content-Type: application/json" \
  -d '{"ip":"198.51.100.99","reason":"Confirmed scraper"}'
```

### GET /api/feedback/stats

Get feedback loop statistics and current configuration.

**Response:**
```json
{
  "enabled": true,
  "current_threshold": 0.72,
  "min_threshold": 0.5,
  "max_threshold": 0.85,
  "target_fp_rate": 0.01,
  "actual_fp_rate": 0.008,
  "total_outcomes": 1542,
  "true_positives": 1530,
  "false_positives": 12,
  "last_adjustment": "2026-01-29T09:45:00Z",
  "adjustment_count": 5,
  "allowlist_size": 3,
  "fp_ips": 12,
  "tp_ips": 1530
}
```

**Example with curl:**
```bash
curl http://localhost:9092/api/feedback/stats
```

### GET /api/feedback/allowlist

Get all IPs currently in the false positive allowlist.

**Response:**
```json
[
  {
    "ip": "203.0.113.42",
    "expires_at": "2026-01-30T10:15:30Z"
  },
  {
    "ip": "198.51.100.10",
    "expires_at": "2026-01-30T11:20:15Z"
  }
]
```

**Example with curl:**
```bash
curl http://localhost:9092/api/feedback/allowlist
```

---

## Feedback Loop Configuration

The feedback loop system automatically adjusts detection thresholds based on false positive rates.

### Configuration Parameters

Set these in [cmd/analyzer/main.go](../cmd/analyzer/main.go) or via `pkg/analyzer/service.go`:

- **Initial Threshold**: Starting confidence threshold (default: 0.70)
- **Min Threshold**: Minimum allowed threshold (default: 0.50)
- **Max Threshold**: Maximum allowed threshold (default: 0.85)
- **Target FP Rate**: Desired false positive rate (default: 0.01 = 1%)
- **Allowlist TTL**: How long FP IPs stay in allowlist (default: 24h)

### How Threshold Adjustment Works

1. **Collect Outcomes**: System tracks true/false positives in a rolling window
2. **Calculate FP Rate**: `FP Rate = False Positives / (True Positives + False Positives)`
3. **Adjust Threshold**:
   - If FP rate > target (e.g., 1.5%): Increase threshold by 0.02 (be more strict)
   - If FP rate < target (e.g., 0.5%): Decrease threshold by 0.01 (be less strict)
4. **Apply Limits**: Threshold stays within [min_threshold, max_threshold] range
5. **Cooldown**: Adjustments happen at most every 5 minutes

### Tuning Recommendations

#### Lower False Positives (More Conservative)
- Increase `target_fp_rate` to 0.02 (2%)
- Increase `min_threshold` to 0.60
- Result: Fewer blocks, some attackers may slip through

#### Higher Detection Rate (More Aggressive)
- Decrease `target_fp_rate` to 0.005 (0.5%)
- Decrease `max_threshold` to 0.75
- Result: More blocks, higher chance of false positives

#### Typical Production Values
```go
cfg := aidetection.DefaultFeedbackConfig()
cfg.InitialThreshold = 0.70  // Start here
cfg.MinThreshold = 0.50      // Don't go below
cfg.MaxThreshold = 0.85      // Don't go above
cfg.TargetFPRate = 0.01      // Aim for 1% FP rate
cfg.AllowlistTTL = 24 * time.Hour
```

---

## Prometheus Metrics

The feedback loop exports these metrics:

- `packetyeeter_feedback_threshold` - Current detection threshold
- `packetyeeter_feedback_false_positives_total` - Total false positives reported
- `packetyeeter_feedback_true_positives_total` - Total true positives reported
- `packetyeeter_feedback_fp_rate` - Current false positive rate (0-1)
- `packetyeeter_feedback_adjustments_total` - Number of threshold adjustments
- `packetyeeter_feedback_allowlist_size` - Current allowlist size

**Example Prometheus query:**
```promql
# False positive rate over last hour
rate(packetyeeter_feedback_false_positives_total[1h]) / 
(rate(packetyeeter_feedback_false_positives_total[1h]) + 
 rate(packetyeeter_feedback_true_positives_total[1h]))

# Threshold changes
delta(packetyeeter_feedback_threshold[1h])
```

---

## Recommended Prometheus Alerts

```yaml
groups:
  - name: packetyeeter_feedback
    rules:
      - alert: HighFalsePositiveRate
        expr: packetyeeter_feedback_fp_rate > 0.02
        for: 10m
        annotations:
          summary: "False positive rate >2% for 10 minutes"
          description: "Current FP rate: {{ $value | humanizePercentage }}"
      
      - alert: ThresholdStuckAtMax
        expr: packetyeeter_feedback_threshold > 0.84
        for: 30m
        annotations:
          summary: "Detection threshold stuck at maximum"
          description: "Threshold has been >0.84 for 30 minutes - feedback loop may be broken"
      
      - alert: ThresholdStuckAtMin
        expr: packetyeeter_feedback_threshold < 0.51
        for: 30m
        annotations:
          summary: "Detection threshold stuck at minimum"
          description: "Threshold has been <0.51 for 30 minutes - may be missing true positives"
      
      - alert: LargeAllowlist
        expr: packetyeeter_feedback_allowlist_size > 100
        for: 1h
        annotations:
          summary: "Allowlist has >100 entries"
          description: "Many IPs in allowlist - possible misconfiguration or mass false positives"
```

---

## Example Workflows

### Investigating a Blocked User

1. **User reports being blocked**: They provide their IP address
2. **Check detection details**: `GET /api/ip/{ip}` to see why they were blocked
3. **Review signals**: Look at `signal_breakdown` and `reasons` fields
4. **Report false positive** (if legitimate): `POST /api/feedback/report-fp`
5. **Monitor**: Check `/api/feedback/stats` to see if threshold adjusted

### Monitoring Detection Quality

1. **Check feedback stats**: `GET /api/feedback/stats` regularly
2. **Monitor FP rate**: Should stay near target (default 1%)
3. **Review allowlist**: `GET /api/feedback/allowlist` - should be small (<10 IPs)
4. **Set up Prometheus alerts**: Use recommended alert rules above

### Manual Threshold Adjustment

If automatic adjustment isn't working:

1. **Check stats**: `GET /api/feedback/stats` to see current state
2. **Edit configuration**: Modify [pkg/analyzer/service.go](../pkg/analyzer/service.go):
   ```go
   aiCfg.AIConfidenceThreshold = 0.75 // Increase to reduce FPs
   ```
3. **Restart analyzer**: Changes take effect on restart
4. **Monitor results**: Check detection rates and FP reports

---

## Future Enhancements

Planned API additions:

- `POST /api/feedback/adjust-threshold` - Manual threshold override
- `GET /api/detections/recent?limit=N` - Paginated detection list
- `GET /api/asn/{asn}` - ASN-specific statistics
- `GET /api/ml/model-info` - Current ML model version and accuracy
- WebSocket endpoint for real-time detection stream

---

**Document Version**: 1.0  
**Last Updated**: January 29, 2026
