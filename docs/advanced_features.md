# Advanced Feature Engineering for Bot Detection

## Overview

The original 41-feature model only used aggregated signal counts, which proved insufficient for detecting sophisticated bots. The **advanced feature extraction** system expands this to **100+ behavioral features** that capture temporal patterns, request sequences, and behavioral consistency.

## Problem with Original Approach

The original `train_model.py` only used:
- 3 core features (signal_count, signal_rate, signal_rate_dup)
- 16 signal type counts
- 5 source counts
- 5 derived ratios
- 12 threat intel features

**Total: 41 features**

These are mostly **static aggregates** that don't capture:
- Request timing patterns (bots are too consistent)
- Path enumeration sequences (bots scan systematically)
- Header inconsistencies (bots reuse same UA)
- Behavioral changes over time

## New Feature Categories

### 1. Temporal Features (7 features)

Capture request timing and burst patterns:

```python
temporal_event_count            # Total requests in session
temporal_duration_seconds       # Session length
temporal_avg_inter_request_time # Average time between requests
temporal_std_inter_request_time # Variance in request timing
temporal_burst_coefficient      # std/mean (high = bursty, low = steady)
temporal_requests_per_second    # Request rate
temporal_requests_per_minute    # Request rate (per minute)
```

**Bot indicators:**
- Very low burst coefficient (too consistent)
- Unnaturally steady request rate
- Too fast or too slow for humans

### 2. Path Features (7 features)

Detect enumeration and scanning patterns:

```python
path_unique_paths              # Number of unique URLs
path_diversity                 # unique/total (1.0 = all unique, 0.1 = repetitive)
path_has_numeric_enumeration   # Accessing /1, /2, /3, etc.
path_has_alpha_enumeration     # Accessing /a, /b, /c, etc.
path_avg_path_depth            # Average URL depth (slashes)
path_entropy                   # Shannon entropy of all path characters
path_method_diversity          # GET/POST variety
```

**Bot indicators:**
- High numeric/alpha enumeration
- Very high path diversity (scanning)
- Very low path diversity (attacking one endpoint)

### 3. Header Features (8 features)

Analyze HTTP header consistency:

```python
header_user_agent_consistent      # Same UA across all requests
header_accept_lang_consistent     # Same Accept-Language
header_missing_accept_language    # No Accept-Language header
header_has_bot_keyword_in_ua      # Contains "bot", "crawler", "curl", etc.
header_ua_has_version             # UA contains version number
header_ua_has_platform            # UA mentions OS (Windows/Mac/Linux)
header_ua_length                  # Length of User-Agent string
header_unique_user_agents         # Number of different UAs used
```

**Bot indicators:**
- Missing Accept-Language
- Bot keywords in UA
- No platform/version info
- Multiple different UAs in same session

### 4. JA4 Fingerprint Features (8 features)

TLS/HTTP fingerprint consistency:

```python
ja4_has_ja4                    # Has TLS fingerprint
ja4_has_ja4h                   # Has HTTP fingerprint
ja4_event_count                # Number of events with JA4
ja4h_event_count               # Number of events with JA4H
ja4_consistent                 # Same JA4 across session
ja4h_consistent                # Same JA4H across session
ja4_unique_ja4_count           # Number of different JA4s
ja4_unique_ja4h_count          # Number of different JA4Hs
```

**Bot indicators:**
- Missing fingerprints (tool doesn't support)
- Inconsistent fingerprints (proxying)

### 5. Signal Pattern Features (4 features)

Analyze signal diversity:

```python
signal_diversity               # Unique signal types / total
signal_entropy                 # Shannon entropy of signal distribution
signal_most_common_signal_ratio # Fraction that is most common type
signal_unique_signal_types     # Number of different signal types
```

**Bot indicators:**
- Low diversity (triggering same signal repeatedly)
- High most_common_ratio (one dominant signal)

### 6. Behavioral Change Features (6 features)

Compare behavior before vs after detection:

```python
behavior_pre_request_rate           # Rate before detection
behavior_post_request_rate          # Rate after detection
behavior_rate_change                # Difference in rates
behavior_rate_change_ratio          # Ratio of rates
behavior_burst_change               # Change in burst pattern
behavior_changed_significantly      # Binary: >50% rate change
```

**Bot indicators:**
- Dramatic rate changes (bot adjusting)
- Complete cessation (bot gave up)
- Rate increase (bot escalating)

### 7. Original Detection Features (3 features)

From the original detection:

```python
original_confidence            # ML confidence score
original_signal_count          # Total signals
original_would_block           # Binary: would block decision
```

## Total Feature Count

**Temporal**: 7  
**Path**: 7  
**Header**: 8  
**JA4**: 8  
**Signal**: 4  
**Behavior**: 6  
**Original**: 3  

**Total: ~43 base features**

Plus additional derived features based on combinations and ratios.

## Usage

### Step 1: Extract Features

```bash
python3 scripts/extract_advanced_features.py \
    --sessions /var/cache/packetyeeter/sessions \
    --output /tmp/advanced_features.jsonl
```

### Step 2: Train Model

```bash
python3 scripts/train_advanced_model.py \
    --input /tmp/advanced_features.jsonl \
    --output /var/lib/packetyeeter/bot_detection_model_v2.json \
    --onnx /var/lib/packetyeeter/bot_detection_model_v2.onnx
```

### Step 3: Full Pipeline

```bash
./scripts/train_advanced_pipeline.sh
```

This runs both steps automatically.

## Expected Improvements

The advanced features should capture:

1. **Timing patterns** - Humans are variable, bots are consistent
2. **Enumeration** - Bots systematically scan paths
3. **Header anomalies** - Bots often have suspicious UAs
4. **Behavioral consistency** - Bots don't adapt like humans
5. **Sequential patterns** - Request order matters

## Model Comparison

To compare old vs new model:

```bash
# Test old model
python3 scripts/test_on_sessions.py \
    --sessions /var/cache/packetyeeter/sessions \
    --model /var/lib/packetyeeter/bot_detection_model.onnx

# Test new model
python3 scripts/test_on_sessions.py \
    --sessions /var/cache/packetyeeter/sessions \
    --model /var/lib/packetyeeter/bot_detection_model_v2.onnx
```

Look for:
- **Lower agreement** (models disagree = new features add value)
- **Better precision/recall on bot class**
- **Lower false positive rate**
- **Higher confidence on true positives**

## Next Steps

If the advanced model still shows 100% agreement with baseline:

1. **Check feature extraction** - Print actual feature values to verify variance
2. **Verify training data** - Ensure labeled sessions have behavioral diversity
3. **Add more features**:
   - Cookie patterns
   - Referer consistency
   - Response time sensitivity
   - Protocol version patterns
   - Connection reuse behavior

4. **Consider sequence models** - LSTM/RNN for temporal patterns
5. **Ensemble methods** - Combine multiple models
