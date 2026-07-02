# ML Feature Specification

**CRITICAL**: This document defines the exact feature vector format used for ML model training and inference. Any changes to this spec require updating BOTH files:
- `scripts/train_model.py` - Training script
- `pkg/ml/onnx.go` - Inference code

## Feature Vector Layout (29 features total)

### Core Features (3)
| Index | Feature Name | Type | Description | Python | Go |
|-------|-------------|------|-------------|--------|-----|
| 0 | `signal_count` | int | Total number of detection signals | `row.get('signal_count', 0)` | `features.SignalCount` |
| 1 | `confidence` | float | Rule-based confidence score | `row.get('confidence', 0.0)` | `features.SignalRate` (proxy during inference) |
| 2 | `ml_confidence` | float | ML model confidence score | `row.get('ml_confidence', 0.0)` | `features.SignalRate` (proxy during inference) |

**Note**: During inference, confidence values aren't available yet (they're the output!), so we use `SignalRate` as a proxy. During training, we use the actual confidence from labeled data.

### Signal Type Features (16)
One-hot encoded signal type counts. **Order matters!**

| Index | Feature Name | Go SignalType | String Output |
|-------|-------------|---------------|---------------|
| 3 | `sig_high_frequency` | `SignalHighFrequency` | `"high_frequency"` |
| 4 | `sig_path_seq_ids` | `SignalPathSeqIDs` | `"path_seq_ids"` |
| 5 | `sig_missing_accept_language` | `SignalMissingAcceptLang` | `"missing_accept_language"` |
| 6 | `sig_clock_skew_anomaly` | `SignalClockSkewAnomaly` | `"clock_skew_anomaly"` |
| 7 | `sig_entropy_low` | `SignalEntropyLow` | `"entropy_low"` |
| 8 | `sig_high_threat_score` | `SignalHighThreatScore` | `"high_threat_score"` |
| 9 | `sig_ua_suspicious` | `SignalSuspiciousUA` | `"ua_suspicious"` |
| 10 | `sig_missing_ja4h` | `SignalMissingJA4H` | `"missing_ja4h"` |
| 11 | `sig_incomplete_handshake` | `SignalIncompleteHandshake` | `"incomplete_handshake"` |
| 12 | `sig_bad_flags` | `SignalBadFlags` | `"bad_flags"` |
| 13 | `sig_connection_pattern` | `SignalConnectionPattern` | `"connection_pattern"` |
| 14 | `sig_timing_pattern` | `SignalTimingPattern` | `"timing_pattern"` |
| 15 | `sig_proxy_lag` | `SignalProxyLag` | `"proxy_lag"` |
| 16 | `sig_icmp_flood` | `SignalICMPFlood` | `"icmp_flood"` |
| 17 | `sig_udp_flood` | `SignalUDPFlood` | `"udp_flood"` |
| 18 | `sig_syn_flood` | `SignalSYNFlood` | `"syn_flood"` |

### Source Breakdown Features (5)
Signal source counts. **Order matters!**

| Index | Feature Name | Go SignalSource | String Output |
|-------|-------------|-----------------|---------------|
| 19 | `source_spoe` | `SourceSPOE` | `"spoe"` |
| 20 | `source_tcp` | `SourceTCP` | `"tcp"` |
| 21 | `source_udp` | `SourceUDP` | `"udp"` |
| 22 | `source_icmp` | `SourceICMP` | `"icmp"` |
| 23 | `source_fingerprint` | `SourceFingerprint` | `"fingerprint"` |

### Derived Features (5)
Computed from signal breakdown.

| Index | Feature Name | Type | Calculation |
|-------|-------------|------|-------------|
| 24 | `sig_diversity` | float | `unique_signals / total_signal_types` |
| 25 | `high_freq_ratio` | float | `high_frequency_count / total_signals` |
| 26 | `enum_ratio` | float | `path_seq_ids_count / total_signals` |
| 27 | `ddos_signals` | int | `icmp_flood + udp_flood + syn_flood` |
| 28 | `scraper_signals` | int | `path_seq_ids + missing_accept_language` |

## Validation Checks

### Python (train_model.py)
```python
expected_features = 29
if X_df.shape[1] != expected_features:
    raise ValueError(f"Feature count mismatch! Expected {expected_features}, got {X_df.shape[1]}")
```

### Go (onnx.go)
```go
if len(tensor) != m.nFeatures {
    logrus.Error("CRITICAL: Feature count mismatch!")
}
```

## Common Pitfalls

1. **❌ Signal Name Mismatch**: Python uses the string output of Go types (e.g., `"high_frequency"` not `"http_high_frequency"`)
2. **❌ Source Name Mismatch**: Must use `"spoe"` not `"http"`, `"fingerprint"` not `"ebpf"`
3. **❌ Feature Order**: Order must be identical between training and inference
4. **❌ Feature Count**: Adding/removing features requires updating both files
5. **❌ Confidence Mapping**: Training uses actual confidence values, inference uses `SignalRate` proxy

## Testing New Models

Before deploying a newly trained model:

1. ✅ Verify feature count is exactly 29
2. ✅ Check all signal type names match the spec
3. ✅ Check all source names match the spec  
4. ✅ Test inference with sample data
5. ✅ Validate predictions are reasonable (not all 0 or all 1)

## Changelog

- **2026-01-29**: Fixed signal/source name mismatches, removed session features, standardized to 29 features
- **Initial**: 32 features (had session features that were always 0)
