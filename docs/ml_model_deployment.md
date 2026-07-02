# ML Model Deployment Guide

## Overview

The PacketYeeter ML model is used to **enhance** detection accuracy, not replace rule-based detection. It works as follows:

### How the ML Model Works

1. **ML Provides Confidence Boost**: The ML model runs **alongside** rule-based detection
2. **Weighted Combination**: Final confidence = `(ML confidence × 60%) + (rule confidence × 40%)`
3. **Cannot Label as "Good"**: The ML model only increases bot probability, it **cannot override** signals to mark traffic as legitimate
4. **Minimum Signal Requirement**: ML only runs if there are already detection signals present

### Detection Flow

```
Incoming Traffic
    ↓
Rule-Based Signals (HTTP analysis, JA4, entropy, etc.)
    ↓
If signals exist:
    ├─→ Extract ML Features
    ├─→ ML Model predicts bot probability
    ├─→ Combine: 60% ML + 40% Rules
    └─→ Final confidence score
    ↓
If confidence > threshold: BLOCK
```

**Important**: The ML model cannot "override" detections to mark traffic as legitimate. It only adjusts the confidence score upward when it detects bot-like patterns.

## Current Model (Built-in Threshold Model)

By default, PacketYeeter uses a **SimpleThresholdModel** defined in `pkg/ml/model.go`. This model:

- ✅ Works out-of-the-box (no training needed)
- ✅ Uses weighted feature scoring
- ✅ Adapts via online learning from feedback
- ✅ Provides baseline bot categorization

## Loading a Custom Trained Model

### Step 1: Train the Model

Use the training script with your labeled data:

```bash
# Collect labeled data from false positive reports
ssh webfrontend03.ov.ffmuc.net 'sudo cat /var/lib/packetyeeter/labeled_dataset.jsonl' > labeled_data.jsonl

# Train the model (requires Python 3.11/3.12)
python3 scripts/train_model.py \
    --input labeled_data.jsonl \
    --output model.pkl \
    --model rf \
    --min-samples 100
```

### Step 2: Implement Custom Model Loader

Currently, PacketYeeter doesn't have a built-in loader for external models. You need to:

**Option A: Extend the SimpleThresholdModel** (Recommended for now)

The threshold model already learns from feedback via the `Train()` method. As you report false positives and true positives:
- The model adapts its mean/stddev parameters
- Threshold adjustments happen automatically
- No external model file needed

**Option B: Implement ONNX Model Loader** (Future enhancement)

Create `pkg/ml/onnx.go` to load your trained model:

```go
package ml

import (
    "github.com/yalue/onnxruntime_go"
    "PacketYeeter/pkg/analyzer/aidetection"
)

type ONNXModel struct {
    session *onnxruntime.Session
    // ... implementation
}

func LoadONNXModel(path string) (*ONNXModel, error) {
    // Load ONNX model from file
    // Initialize session
    // Return model wrapper
}

func (m *ONNXModel) Predict(features aidetection.MLFeatures) aidetection.MLPredictionResult {
    // Convert features to input tensor
    // Run inference
    // Return prediction
}
```

Then modify `pkg/analyzer/service.go` to load the custom model:

```go
// In analyzer initialization
if modelPath := os.Getenv("ML_MODEL_PATH"); modelPath != "" {
    customModel, err := ml.LoadONNXModel(modelPath)
    if err == nil {
        analyzer.AIEngine.SetMLModel(customModel)
    }
}
```

### Step 3: Deploy

After implementing the loader:

```bash
# Set environment variable in service file
sudo nano /etc/default/packetyeeter-analyzer

# Add:
ML_MODEL_PATH=/var/lib/packetyeeter/model.onnx

# Copy model to server
scp model.onnx webfrontend03.ov.ffmuc.net:/tmp/
ssh webfrontend03.ov.ffmuc.net 'sudo mv /tmp/model.onnx /var/lib/packetyeeter/'

# Restart analyzer
sudo systemctl restart packetyeeter-analyzer
```

## Model Behavior & Precedence

### Can the ML Model Override Detections?

**NO** - The ML model cannot label traffic as legitimate if signals are present. Here's why:

1. **ML only runs after signals exist**: If there are no detection signals, ML doesn't run
2. **ML increases confidence**: ML predictions are combined with rule confidence, not used alone
3. **Feedback loop handles false positives**: When you mark something as false positive:
   - IP goes on 24h allowlist (bypasses detection entirely)
   - Detection is labeled as "human" for retraining
   - ML model learns from this via `Train(features, false)`

### Precedence Order

1. **Allowlist** (highest priority)
   - IPs marked as false positive
   - Bypasses all detection for 24 hours

2. **Verification** 
   - DNS verification for claimed crawlers
   - Can reduce confidence or override category

3. **Rule-Based Signals**
   - JA4 fingerprinting, entropy, rate limiting, etc.
   - Generate base confidence score

4. **ML Model Enhancement**
   - Adjusts confidence if bot-like patterns detected
   - Cannot reduce confidence below rule-based score
   - Weighted combination: 60% ML + 40% Rules

5. **Final Threshold Check**
   - If confidence > threshold (default 65%): BLOCK

### Example Scenarios

#### Scenario 1: High Signal Count, Low ML Confidence
```
Rule-based: 8 signals, confidence 0.70
ML predicts: confidence 0.40 (uncertain)
Final: (0.40 × 0.6) + (0.70 × 0.4) = 0.52
Result: NOT BLOCKED (below 0.65 threshold)
```

#### Scenario 2: Moderate Signals, High ML Confidence
```
Rule-based: 4 signals, confidence 0.55
ML predicts: confidence 0.85 (strong bot pattern)
Final: (0.85 × 0.6) + (0.55 × 0.4) = 0.73
Result: BLOCKED (above 0.65 threshold)
```

#### Scenario 3: False Positive Reported
```
User marks IP as false positive
→ IP added to allowlist for 24h
→ All future traffic from IP bypasses detection
→ Detection saved with label="human" to /var/lib/packetyeeter/labeled_dataset.jsonl
→ ML model retrains with Train(features, false)
```

## Monitoring Model Performance

### Check ML Metrics

```bash
# View Prometheus metrics
curl http://localhost:9091/metrics | grep ml_

# Key metrics:
# - ml_bot_detections_total: Total bot detections by ML
# - ml_confidence_by_category: Confidence distribution
# - ml_prediction_total: Total predictions made
```

### View Training Data

```bash
# Check labeled dataset
ssh webfrontend03.ov.ffmuc.net 'sudo cat /var/lib/packetyeeter/labeled_dataset.jsonl | jq .'

# Count labels
ssh webfrontend03.ov.ffmuc.net 'sudo cat /var/lib/packetyeeter/labeled_dataset.jsonl | jq -r .label | sort | uniq -c'
```

### False Positive Rate

Check the Feedback Loop tab in the web interface:
- Target: 1.0% FP rate
- Threshold auto-adjusts based on FP rate
- View stats at http://webfrontend03.ov.ffmuc.net:9092 → Feedback Loop tab

## Best Practices

1. **Start with Built-in Model**: The SimpleThresholdModel adapts automatically via feedback
2. **Collect Data First**: Aim for 1000+ labeled samples before training custom model
3. **Balance Dataset**: Try to get 50/50 bot/human ratio when training
4. **Monitor FP Rate**: Keep false positive rate below 2%
5. **Use A/B Testing**: Test new models on 10% traffic before full rollout
6. **Regular Retraining**: Retrain monthly with fresh labeled data

## Troubleshooting

### ML Model Not Running

```bash
# Check if ML is enabled
curl http://localhost:9091/metrics | grep ml_enabled

# Check logs
sudo journalctl -u packetyeeter-analyzer -f | grep ML
```

### High False Positive Rate

1. Check feedback stats in web UI
2. Increase confidence threshold:
   ```bash
   # In /etc/default/packetyeeter-analyzer
   AI_CONFIDENCE_THRESHOLD=0.75  # Default is 0.65
   ```
3. Review recent false positives:
   ```bash
   sudo cat /var/lib/packetyeeter/labeled_dataset.jsonl | jq 'select(.label=="human")'
   ```

### Model Not Learning

- Verify `/var/lib/packetyeeter/labeled_dataset.jsonl` is being written
- Check file permissions: `sudo chmod 644 /var/lib/packetyeeter/labeled_dataset.jsonl`
- Review analyzer logs for errors: `sudo journalctl -u packetyeeter-analyzer -n 100`

## Future Enhancements

- [ ] ONNX model loader implementation
- [ ] Hot-reload model without restart
- [ ] Model versioning and rollback
- [ ] Automated retraining pipeline
- [ ] Model drift detection
- [ ] Feature importance tracking
