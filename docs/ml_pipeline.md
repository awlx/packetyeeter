# Machine Learning Pipeline

This directory contains tools for training and deploying ML models for PacketYeeter bot detection.

## Overview

The ML pipeline consists of three main components:

1. **Data Collection**: Export detection events from the analyzer
2. **Labeling**: Human-in-the-loop labeling of bot vs human traffic
3. **Training**: Train RandomForest/XGBoost models on labeled data
4. **Deployment**: Export to ONNX and deploy to production

---

## Quick Start

### 1. Collect Detection Data

First, export detection events from the analyzer. Add this to your analyzer code:

```go
// In pkg/analyzer/service.go or similar
func (a *Analyzer) ExportDetections(outputPath string) error {
    detections := a.AIEngine.GetAllLatestDetections()
    
    file, err := os.Create(outputPath)
    if err != nil {
        return err
    }
    defer file.Close()
    
    encoder := json.NewEncoder(file)
    for _, det := range detections {
        if err := encoder.Encode(det); err != nil {
            return err
        }
    }
    return nil
}
```

Or fetch via API:

```bash
curl http://localhost:9092/api/detections > detections.json
```

### 2. Label the Data

Use the labeling tool to classify traffic as bot or human:

```bash
# Build the labeling tool
go build -o labeler cmd/labeler/main.go

# Start labeling
./labeler --input detections.json --output labeled_dataset.jsonl
```

**Labeling Interface:**
- Press `h` for human (legitimate user)
- Press `b` for bot (malicious/unwanted)
- Press `u` for unknown
- Press `s` to skip
- Press `q` to quit

For bots, you'll be asked to classify the bot type:
1. Scraper (content extraction)
2. DDoS (flood attack)
3. Crawler (systematic exploration)
4. Spam/Brute force
5. Vulnerability scanner
6. Other

**Tip:** Label at least 1000 samples for a good model. Aim for 50/50 bot/human balance.

### 3. Train the Model

Install Python dependencies:

```bash
pip install scikit-learn xgboost pandas numpy onnx skl2onnx
```

Train a Random Forest model:

```bash
python scripts/train_model.py \
  --input labeled_dataset.jsonl \
  --output model.pkl \
  --model rf
```

Or train XGBoost:

```bash
python scripts/train_model.py \
  --input labeled_dataset.jsonl \
  --output model.pkl \
  --model xgb
```

Or compare both:

```bash
python scripts/train_model.py \
  --input labeled_dataset.jsonl \
  --output model.pkl \
  --model both
```

**Training Output:**
- `model.pkl` - Serialized scikit-learn model
- `model_metadata.json` - Model metadata (accuracy, features, etc.)
- Console output with confusion matrix and classification report

### 4. Export to ONNX (Optional)

For production deployment, export to ONNX format:

```bash
python scripts/train_model.py \
  --input labeled_dataset.jsonl \
  --output model.onnx \
  --model rf
```

**Note:** ONNX export requires Go ONNX runtime bindings. See [pkg/ml/onnx.go](../pkg/ml/onnx.go) for installation instructions.

### 5. Deploy to Production

#### Option A: Use Pickle Model (Python)

```go
// Not directly supported - requires Python/Go bridge
// Consider using ONNX instead
```

#### Option B: Use ONNX Model (Recommended)

```go
import "PacketYeeter/pkg/ml"

// Load ONNX model
model, err := ml.LoadONNXModel("model.onnx", 0.7)
if err != nil {
    log.Fatal(err)
}
defer model.Close()

// Use in analyzer config
cfg := analyzer.Config{
    MLModel: model,
    // ... other config
}
```

#### Option C: Retrain Simple Model in Go

Convert your labeled dataset to Go-native training:

```go
// TODO: Implement Go-native training
// For now, use threshold model or ONNX
```

---

## A/B Testing

Test a new model against the production model:

### 1. Train New Model

```bash
python scripts/train_model.py \
  --input new_labeled_dataset.jsonl \
  --output model_v2.onnx \
  --model rf
```

### 2. Enable A/B Testing

```go
primaryModel, _ := ml.LoadONNXModel("model_v1.onnx", 0.7)
testModel, _ := ml.LoadONNXModel("model_v2.onnx", 0.7)

cfg := analyzer.Config{
    MLModel:          primaryModel,
    EnableABTest:     true,
    ABTestModel:      testModel,
    ABTestPercentage: 0.1, // Route 10% of traffic to test model
}
```

### 3. Monitor Metrics

```promql
# Primary model predictions
rate(packetyeeter_ml_ab_test_predictions_total{model="primary_model"}[5m])

# Test model predictions
rate(packetyeeter_ml_ab_test_predictions_total{model="test_model"}[5m])

# Cases where models disagree
rate(packetyeeter_ml_ab_test_discrepancies_total[5m])
```

### 4. Analyze Results

Compare false positive rates, accuracy, and detection rates:

```bash
# Check feedback stats
curl http://localhost:9092/api/feedback/stats

# Check primary model FP rate
curl http://localhost:9092/api/feedback/stats | jq '.actual_fp_rate'
```

If the test model performs better, promote it to primary:

```go
cfg.MLModel = testModel
cfg.EnableABTest = false
```

---

## Feature Engineering

The ML model uses these features (total: ~50):

### Core Features (8)
- `signal_count` - Total signals received
- `signal_rate` - Signals per second
- `signal_diversity` - Percentage of unique signal types
- `source_diversity` - Percentage of unique sources
- `time_span` - Time span of signals
- `is_bursty` - Boolean: signals are bursty
- `time_of_day` - Hour of day (0-23)
- `day_of_week` - Day of week (0-6)

### Signal Type Features (16 one-hot encoded)
- `http_high_frequency`, `path_enumeration`, `missing_static_assets`
- `clock_skew`, `entropy_anomaly`, `reputation_penalty`
- `suspicious_ua`, `ja4_mismatch`, `incomplete_handshake`
- `bad_flags`, `connection_pattern`, `timing_anomaly`
- `http_method_anomaly`, `icmp_flood`, `udp_flood`, `syn_flood`

### Source Breakdown (5)
- `http`, `tcp`, `udp`, `icmp`, `ebpf`

### Derived Features (4)
- `high_freq_ratio` - Ratio of high-frequency signals
- `enum_ratio` - Ratio of path enumeration signals
- `ddos_signals` - Sum of flood signals
- `scraper_signals` - Sum of scraper signals

### Network Features (2)
- `has_asn` - Boolean: ASN available
- `has_ja4h` - Boolean: JA4H fingerprint available

### Behavioral Features (3)
- `request_rate` - HTTP request rate
- `detection_history` - Prior detections
- `reputation_score` - IP reputation score

### Threat Intel Features (7)
- `threat_score` - Shodan threat score
- `is_known_scanner` - Boolean: known scanner
- `is_cloud` - Boolean: cloud provider
- `is_tor` - Boolean: Tor exit node
- `is_vpn` - Boolean: VPN provider
- `has_vulnerabilities` - Boolean: has vulns
- `open_port_count` - Number of open ports

---

## Model Evaluation

### Key Metrics

- **Accuracy**: Percentage of correct predictions
- **Precision**: Of predicted bots, how many are actually bots? (minimize false positives)
- **Recall**: Of actual bots, how many did we detect? (minimize false negatives)
- **F1 Score**: Harmonic mean of precision and recall

### Target Metrics

For production deployment, aim for:

- **Accuracy**: >95%
- **Precision**: >98% (false positive rate <2%)
- **Recall**: >90% (detect at least 90% of bots)
- **F1 Score**: >0.94

### Confusion Matrix

```
                Predicted Human    Predicted Bot
Actual Human          TN               FP
Actual Bot            FN               TP
```

- **TN (True Negative)**: Correctly classified humans
- **FP (False Positive)**: Humans misclassified as bots (BAD - blocks legitimate users)
- **FN (False Negative)**: Bots misclassified as humans (OKAY - some bots slip through)
- **TP (True Positive)**: Correctly classified bots

**Priority:** Minimize FP > Maximize TP

---

## Continuous Improvement

### Weekly Retraining

1. Export detections from past week
2. Label new samples (focus on false positives)
3. Merge with existing dataset
4. Retrain model
5. A/B test new model
6. Deploy if better

### Monitoring

Set up alerts for:

- False positive rate >2%
- Model accuracy drops <90%
- A/B test discrepancy rate >20%

### Feedback Loop

The system includes an adaptive feedback loop that:

- Automatically adjusts thresholds based on FP rate
- Maintains a 24h allowlist for reported false positives
- Targets 1% FP rate by default

Monitor feedback stats:

```bash
curl http://localhost:9092/api/feedback/stats
```

---

## Troubleshooting

### "Not enough samples"

- Need at least 100 labeled samples (default)
- Aim for 1000+ for production
- Collect more data before training

### "Imbalanced dataset"

- Bot ratio should be 20-80%
- If <10% bots: Collect more bot samples
- If >90% bots: Collect more human samples
- Use class weights in training

### "Low accuracy"

- Check feature importance - are useful features included?
- Try different models (RF vs XGBoost)
- Tune hyperparameters (max_depth, n_estimators)
- Add more features (e.g., more threat intel)

### "High false positive rate"

- Increase classification threshold (0.7 → 0.8)
- Review false positive cases - find patterns
- Add more human samples to training data
- Enable feedback loop for automatic adjustment

---

## References

- [scikit-learn Documentation](https://scikit-learn.org/)
- [XGBoost Documentation](https://xgboost.readthedocs.io/)
- [ONNX Runtime](https://onnxruntime.ai/)
- [ONNX Runtime Go Bindings](https://github.com/yalue/onnxruntime_go)

---

**Last Updated:** January 29, 2026
