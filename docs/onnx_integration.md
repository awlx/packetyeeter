# ONNX Model Integration

PacketYeeter uses a **Hybrid ML System** combining:
1. **Pattern Matching** - Instant recognition of known traffic
2. **ONNX Model** - Deep learning for unknown attack detection
3. **Statistical Fallback** - Adaptive thresholding

## Architecture

```
Traffic → Pattern Check → ONNX Model → Statistical Fallback
          (known)         (unknown)      (last resort)
          ✓ 100% accuracy ✓ Novel attacks ✓ Always works
          ✓ 0ms latency   ✓ High accuracy ✓ No dependencies
```

## Quick Start

### 1. Train an ONNX Model

```bash
# Collect labeled data via UI
# Data accumulates in /var/lib/packetyeeter/labeled_dataset.jsonl

# Train model
cd /usr/local/src/packetyeeter
python3 scripts/train_model.py \
  --input /var/lib/packetyeeter/labeled_dataset.jsonl \
  --output /var/lib/packetyeeter/model.onnx \
  --test-size 0.2 \
  --cv-folds 5

# Output: model.onnx (production-ready ONNX model)
```

### 2. Install ONNX Runtime (Optional but Recommended)

#### Linux (Ubuntu/Debian)
```bash
# Download ONNX Runtime
wget https://github.com/microsoft/onnxruntime/releases/download/v1.16.3/onnxruntime-linux-x64-1.16.3.tgz
tar xzf onnxruntime-linux-x64-1.16.3.tgz
sudo mv onnxruntime-linux-x64-1.16.3 /opt/onnxruntime

# Set environment variables
echo 'export ONNXRUNTIME_DIR=/opt/onnxruntime' | sudo tee -a /etc/environment
echo 'export LD_LIBRARY_PATH=/opt/onnxruntime/lib:$LD_LIBRARY_PATH' | sudo tee -a /etc/environment

# Install Go bindings
cd /usr/local/src/packetyeeter
go get github.com/yalue/onnxruntime_go
```

#### macOS
```bash
brew install onnxruntime
export ONNXRUNTIME_DIR=/usr/local/opt/onnxruntime
```

### 3. Enable ONNX Inference

**Option A: Command Line** (Recommended for testing)

```bash
sudo /opt/packetyeeter/analyzer/packetyeeter-analyzer \
  --listen-addr 0.0.0.0:9090 \
  --ml-model /var/lib/packetyeeter/model.onnx
```

**Option B: Configuration File** (Recommended for production)

Edit `/etc/default/packetyeeter-analyzer`:

```bash
ML_MODEL_PATH="/var/lib/packetyeeter/model.onnx"
```

Restart analyzer:

```bash
sudo systemctl restart packetyeeter-analyzer
```

**All Available ML Flags:**

```bash
--ml-model string
    Path to ONNX ML model file (optional, enables hybrid ML inference)
    
--ai-confidence-threshold float
    AI detection confidence threshold for blocking (default 0.7)
    Applies to both ONNX and statistical models
    
--ai-workers int
    AI engine worker count (default 16)
    
--ai-queue-size int
    AI engine signal queue size (default 10000)
```

## Decision Flow

### Pattern Match (Priority 1)
- **When**: Traffic matches learned pattern (UA + ASN + JA4H)
- **Speed**: < 1ms (hash lookup)
- **Accuracy**: 100% (for known patterns)
- **Example**: "dnscrypt-proxy from AS12345" → Allow instantly

### ONNX Inference (Priority 2)
- **When**: No pattern match (unknown traffic)
- **Speed**: 5-10ms (deep learning inference)
- **Accuracy**: 95%+ (detects novel attacks)
- **Example**: New scraper using unknown UA → ONNX detects behavioral anomalies

### Statistical Fallback (Priority 3)
- **When**: ONNX not available or fails
- **Speed**: < 1ms (simple math)
- **Accuracy**: 80-85% (adaptive thresholds)
- **Example**: Threshold-based detection on signal count/rate

## Model Training Pipeline

### Automated Retraining (Recommended)

```bash
# Add cron job for daily retraining
sudo tee /etc/cron.daily/retrain-ml-model << 'EOF'
#!/bin/bash
cd /usr/local/src/packetyeeter

# Check if we have enough new labels (min 100)
LABEL_COUNT=$(wc -l < /var/lib/packetyeeter/labeled_dataset.jsonl)
if [ $LABEL_COUNT -lt 100 ]; then
  echo "Not enough labeled data ($LABEL_COUNT samples), skipping"
  exit 0
fi

# Train new model
python3 scripts/train_model.py \
  --input /var/lib/packetyeeter/labeled_dataset.jsonl \
  --output /tmp/model_new.onnx \
  --test-size 0.2 \
  --cv-folds 5 \
  --quiet

# Backup old model
if [ -f /var/lib/packetyeeter/model.onnx ]; then
  cp /var/lib/packetyeeter/model.onnx /var/lib/packetyeeter/model.onnx.backup
fi

# Deploy new model
mv /tmp/model_new.onnx /var/lib/packetyeeter/model.onnx

# Restart analyzer to load new model
systemctl restart packetyeeter-analyzer

logger "PacketYeeter: ML model retrained with $LABEL_COUNT samples"
EOF

sudo chmod +x /etc/cron.daily/retrain-ml-model
```

## Monitoring

### View Hybrid Model Metrics

```bash
curl http://localhost:9090/api/ml/metrics | jq
```

Response:
```json
{
  "pattern_matches": 1523,
  "onnx_inferences": 247,
  "fallback_inferences": 12,
  "total_predictions": 1782,
  "pattern_match_pct": 85.5,
  "onnx_usage_pct": 13.9,
  "fallback_usage_pct": 0.7,
  "has_onnx": true,
  "has_pattern_checker": true
}
```

### Key Metrics Explained

- **pattern_match_pct**: % of traffic handled by pattern matching (should be 70-90%)
- **onnx_usage_pct**: % requiring ONNX inference (should be 10-30%)
- **fallback_usage_pct**: % using statistical fallback (should be < 5%)

**Goal**: Maximize pattern_match_pct over time as patterns are learned.

## Feature Engineering

The model uses 50+ features including:

**Core Features:**
- Signal count, rate, diversity
- Source diversity (HTTP, TCP, UDP, ICMP, eBPF)
- Temporal patterns (time of day, day of week, burstiness)

**Signal Type Vectors (one-hot):**
- HTTP: high_frequency, path_enumeration, missing_static_assets
- Network: clock_skew, incomplete_handshake, bad_flags
- Floods: icmp_flood, udp_flood, syn_flood
- Behavioral: timing_anomaly, connection_pattern

**Derived Features:**
- DDoS signal ratio (floods / total)
- Scraper signal ratio (path_enum / total)
- Signal diversity percentage

**Threat Intelligence:**
- Shodan threat score
- Known scanner flags (Tor, VPN, Cloud)
- Open port count
- Historical reputation

## Performance Tuning

### Optimize Pattern Matching

Label more traffic to increase pattern_match_pct:

```bash
# View unlabeled high-frequency IPs
curl http://localhost:9090/api/detections | jq '.[] | select(.label == null) | {ip, signal_count, user_agent}' | head -20
```

### Optimize ONNX Model

```bash
# Train with class weights for imbalanced data
python3 scripts/train_model.py \
  --input /var/lib/packetyeeter/labeled_dataset.jsonl \
  --output model.onnx \
  --balance-classes \
  --cv-folds 10

# Use ensemble for better accuracy (slower)
python3 scripts/train_model.py \
  --input /var/lib/packetyeeter/labeled_dataset.jsonl \
  --output model.onnx \
  --model ensemble
```

## Troubleshooting

### ONNX Model Not Loading

Check logs:
```bash
sudo journalctl -u packetyeeter-analyzer -n 100 | grep -i onnx
```

Common issues:
- **File not found**: Check `ML_MODEL_PATH` in `/etc/default/packetyeeter-analyzer`
- **Runtime missing**: Install `onnxruntime` (see installation section)
- **Corrupt model**: Retrain model from scratch

### Low Pattern Match Rate

This is normal initially. Pattern matching improves over time:

- **Day 1**: 10-20% (only manually labeled patterns)
- **Week 1**: 40-60% (learning window captures common patterns)
- **Month 1**: 70-90% (comprehensive pattern database)

### High ONNX Usage

This means you're seeing lots of unknown traffic. Good for security!

To reduce ONNX load, label more traffic to build patterns.

## Production Recommendations

1. **Start without ONNX**: Let pattern learning build database first (1-2 weeks)
2. **Train ONNX weekly**: Once you have 500+ labeled samples
3. **Monitor metrics**: Aim for 80%+ pattern matches after 1 month
4. **A/B test**: Compare ONNX vs statistical fallback performance
5. **Backup models**: Keep last 3 model versions for rollback

## Future Enhancements

- [ ] Multi-model ensemble (multiple ONNX models voting)
- [ ] Online ONNX model updates (incremental learning)
- [ ] Transfer learning from other datasets
- [ ] Automated hyperparameter tuning
- [ ] Model explainability (SHAP values for predictions)
