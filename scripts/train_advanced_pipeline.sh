#!/bin/bash
#
# Advanced Bot Detection Training Pipeline
#
# This script orchestrates the complete training workflow using 100+ behavioral features:
# 1. Extract advanced features from session recordings
# 2. Train XGBoost model with temporal, behavioral, and sequential patterns
# 3. Deploy to production
#
# Usage:
#   ./train_advanced_pipeline.sh
#

set -e

# Configuration
SESSIONS_DIR="${SESSIONS_DIR:-/var/cache/packetyeeter/sessions}"
FEATURES_FILE="${FEATURES_FILE:-/tmp/advanced_features.jsonl}"
MODEL_OUTPUT="${MODEL_OUTPUT:-/var/lib/packetyeeter/bot_detection_model_v2.json}"
ONNX_OUTPUT="${ONNX_OUTPUT:-/var/lib/packetyeeter/bot_detection_model_v2.onnx}"
BASE_MODEL="${BASE_MODEL:-}"  # Optional: path to existing model for incremental training

echo "========================================"
echo "Advanced Bot Detection Training Pipeline"
echo "========================================"
echo

# Check for session files
SESSION_COUNT=$(find "$SESSIONS_DIR" -name "recording-*.jsonl" 2>/dev/null | wc -l | tr -d ' ')
if [ "$SESSION_COUNT" -eq 0 ]; then
    echo "ERROR: No session recordings found in $SESSIONS_DIR"
    echo
    echo "To collect training data:"
    echo "  1. Go to Inspector UI: http://your-server:9092"
    echo "  2. Navigate to 'Labeling' tab"
    echo "  3. Mark detections as TP (bot) or FP (human)"
    echo "  4. Click 'Start Recording' for labeled IPs"
    echo "  5. Wait 5 minutes for recordings to complete"
    echo "  6. Run this script again"
    exit 1
fi

echo "Found $SESSION_COUNT session recording files"
echo

# Step 1: Extract advanced features
echo "========================================"
echo "Step 1: Extract Advanced Features"
echo "========================================"
echo "This extracts 100+ behavioral features including:"
echo "  - Temporal patterns (request timing, bursts)"
echo "  - Path diversity (enumeration detection)"
echo "  - Header consistency"
echo "  - User-Agent analysis"
echo "  - JA4/JA4H fingerprints"
echo "  - Signal patterns"
echo

python3 scripts/extract_advanced_features.py \
    --sessions "$SESSIONS_DIR" \
    --output "$FEATURES_FILE"

if [ ! -f "$FEATURES_FILE" ]; then
    echo "ERROR: Feature extraction failed"
    exit 1
fi

# Check number of labeled samples
LABELED_COUNT=$(wc -l < "$FEATURES_FILE" | tr -d ' ')
echo
echo "Extracted features from $LABELED_COUNT labeled sessions"

if [ "$LABELED_COUNT" -lt 50 ]; then
    echo
    echo "WARNING: Only $LABELED_COUNT labeled sessions found"
    echo "Recommendation: Collect at least 100 labeled sessions"
    echo "  - 50+ bot samples (TP)"
    echo "  - 50+ human samples (FP)"
    echo
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Step 2: Train model
echo
echo "========================================"
echo "Step 2: Train XGBoost Model"
echo "========================================"
echo

TRAIN_ARGS="--input $FEATURES_FILE --output $MODEL_OUTPUT --onnx $ONNX_OUTPUT"

if [ -n "$BASE_MODEL" ] && [ -f "$BASE_MODEL" ]; then
    echo "Using incremental training from base model: $BASE_MODEL"
    TRAIN_ARGS="$TRAIN_ARGS --base-model $BASE_MODEL"
fi

python3 scripts/train_advanced_model.py $TRAIN_ARGS

if [ ! -f "$MODEL_OUTPUT" ]; then
    echo "ERROR: Model training failed"
    exit 1
fi

# Step 3: Validate model
echo
echo "========================================"
echo "Step 3: Validate Model"
echo "========================================"
echo

echo "Model file: $MODEL_OUTPUT ($(du -h "$MODEL_OUTPUT" | cut -f1))"
if [ -f "$ONNX_OUTPUT" ]; then
    echo "ONNX file: $ONNX_OUTPUT ($(du -h "$ONNX_OUTPUT" | cut -f1))"
fi

# Step 4: Deploy
echo
echo "========================================"
echo "Step 4: Deploy to Production"
echo "========================================"
echo

# Backup existing model
if [ -f /var/lib/packetyeeter/bot_detection_model.onnx ]; then
    BACKUP_NAME="bot_detection_model.onnx.backup.$(date +%Y%m%d_%H%M%S)"
    echo "Backing up existing model to: $BACKUP_NAME"
    cp /var/lib/packetyeeter/bot_detection_model.onnx "/var/lib/packetyeeter/$BACKUP_NAME"
fi

# Copy new model
echo "Deploying new model..."
cp "$MODEL_OUTPUT" /var/lib/packetyeeter/
if [ -f "$ONNX_OUTPUT" ]; then
    cp "$ONNX_OUTPUT" /var/lib/packetyeeter/bot_detection_model.onnx
fi

echo
echo "========================================"
echo "✓ Training Pipeline Complete!"
echo "========================================"
echo
echo "Next steps:"
echo "  1. Restart analyzer: systemctl restart packetyeeter-analyzer"
echo "  2. Test on sessions: python3 scripts/test_on_sessions.py --model $ONNX_OUTPUT"
echo "  3. Compare models: python3 scripts/evaluate_model.py"
echo
echo "Model deployed to: /var/lib/packetyeeter/bot_detection_model.onnx"
echo
