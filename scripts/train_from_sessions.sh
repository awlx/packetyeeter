#!/bin/bash
set -e

# PacketYeeter Incremental Training Script
# Automatically processes session recordings and trains ML model

# Configuration
SESSIONS_DIR="${SESSIONS_DIR:-/var/cache/packetyeeter/sessions}"
OUTPUT_DIR="${OUTPUT_DIR:-/var/lib/packetyeeter}"
BASE_MODEL="${BASE_MODEL:-$OUTPUT_DIR/model_v2.onnx}"
BASE_MODEL_JSON="${BASE_MODEL_JSON:-$OUTPUT_DIR/model_v2.json}"
TRAINING_DATA="$OUTPUT_DIR/training_data.jsonl"
COMBINED_DATA="$OUTPUT_DIR/combined_training.jsonl"
LABELED_DATASET="$OUTPUT_DIR/labeled_dataset.jsonl"
MIN_SAMPLES="${MIN_SAMPLES:-100}"

echo "=================================================="
echo "PacketYeeter Incremental ML Training"
echo "=================================================="
echo ""
echo "Configuration:"
echo "  Sessions directory: $SESSIONS_DIR"
echo "  Output directory:   $OUTPUT_DIR"
echo "  Base model:         $BASE_MODEL"
echo "  Min samples:        $MIN_SAMPLES"
echo ""

# Check if sessions directory exists
if [ ! -d "$SESSIONS_DIR" ]; then
    echo "❌ Error: Sessions directory not found: $SESSIONS_DIR"
    echo ""
    echo "Make sure you have:"
    echo "  1. Started recording sessions via the Inspector UI"
    echo "  2. The sessions directory exists and is accessible"
    exit 1
fi

# Count session files
SESSION_COUNT=$(find "$SESSIONS_DIR" -name "recording-*.jsonl" -type f 2>/dev/null | wc -l | tr -d ' ')

if [ "$SESSION_COUNT" -eq 0 ]; then
    echo "❌ No session recordings found in $SESSIONS_DIR"
    echo ""
    echo "To create session recordings:"
    echo "  1. Open Inspector UI: http://your-server:9092"
    echo "  2. Go to Statistics tab"
    echo "  3. Click 'Record All' to record labeled IPs"
    echo "  4. Or manually start recording for specific IPs"
    echo "  5. Wait for recordings to complete (5 minutes each)"
    exit 1
fi

echo "📁 Found $SESSION_COUNT session recording files"
echo ""

# Step 1: Convert sessions to training data
echo "Step 1/4: Converting session recordings to training format..."
python3 scripts/sessions_to_training.py \
    --sessions-dir "$SESSIONS_DIR" \
    --output "$TRAINING_DATA" \
    || { echo "❌ Failed to convert sessions"; exit 1; }

echo ""

# Check if training data was created
if [ ! -f "$TRAINING_DATA" ]; then
    echo "❌ Error: Training data file was not created"
    exit 1
fi

TRAINING_SAMPLES=$(wc -l < "$TRAINING_DATA" | tr -d ' ')
echo "✅ Created training data with $TRAINING_SAMPLES samples"
echo ""

# Step 2: Combine with existing labeled dataset (if exists)
echo "Step 2/4: Combining with existing labeled dataset..."
if [ -f "$LABELED_DATASET" ]; then
    LABELED_SAMPLES=$(wc -l < "$LABELED_DATASET" | tr -d ' ')
    echo "  Found existing labeled dataset: $LABELED_SAMPLES samples"
    
    # Combine both datasets
    cat "$LABELED_DATASET" "$TRAINING_DATA" > "$COMBINED_DATA"
    COMBINED_SAMPLES=$(wc -l < "$COMBINED_DATA" | tr -d ' ')
    
    echo "✅ Combined dataset: $COMBINED_SAMPLES total samples"
    TRAIN_INPUT="$COMBINED_DATA"
else
    echo "  No existing labeled dataset found, using session data only"
    TRAIN_INPUT="$TRAINING_DATA"
    COMBINED_SAMPLES=$TRAINING_SAMPLES
fi
echo ""

# Check minimum samples
if [ "$COMBINED_SAMPLES" -lt "$MIN_SAMPLES" ]; then
    echo "⚠️  Warning: Only $COMBINED_SAMPLES samples available (minimum: $MIN_SAMPLES)"
    echo ""
    echo "For better model performance:"
    echo "  - Record more sessions (at least 50 legitimate + 50 malicious)"
    echo "  - Label more detections in the Inspector UI"
    echo "  - Wait for more traffic to be detected"
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Training cancelled"
        exit 1
    fi
fi

# Step 3: Check for existing model for incremental training
echo "Step 3/4: Checking for base model..."
BASE_MODEL_ARG=""
if [ -f "$BASE_MODEL_JSON" ]; then
    echo "✅ Found existing XGBoost model: $BASE_MODEL_JSON"
    echo "   Will perform incremental training (warm start)"
    BASE_MODEL_ARG="--base-model $BASE_MODEL_JSON"
elif [ -f "$BASE_MODEL" ]; then
    echo "  Found ONNX model, but need .json for incremental training"
    echo "  Will train from scratch this time"
else
    echo "  No existing model found, will train from scratch"
fi
echo ""

# Step 4: Train model
echo "Step 4/4: Training XGBoost model..."
echo "  Input:  $TRAIN_INPUT"
echo "  Output: $BASE_MODEL"
echo "  Samples: $COMBINED_SAMPLES"
echo ""

python3 scripts/train_model.py \
    --input "$TRAIN_INPUT" \
    --output "$BASE_MODEL" \
    --model xgb \
    --min-samples "$MIN_SAMPLES" \
    $BASE_MODEL_ARG \
    || { echo "❌ Training failed"; exit 1; }

echo ""
echo "=================================================="
echo "✅ Training Complete!"
echo "=================================================="
echo ""
echo "Model saved to: $BASE_MODEL"
echo "Training data:  $TRAIN_INPUT"
echo "Total samples:  $COMBINED_SAMPLES"
echo ""
echo "Next steps:"
echo "  1. Test model performance:"
echo "     python3 scripts/test_model.py --model $BASE_MODEL"
echo ""
echo "  2. Deploy model (automatic hot-reload):"
echo "     Model watcher will detect changes and reload automatically"
echo "     Watch logs: journalctl -u packetyeeter-analyzer -f"
echo ""
echo "  3. Monitor performance:"
echo "     - Check false positive rate in Inspector UI (Feedback Loop tab)"
echo "     - Review detection accuracy on live traffic"
echo "     - Collect more labeled samples if needed"
echo ""
echo "  4. Continue improving:"
echo "     - Record more sessions with different traffic patterns"
echo "     - Label more detections (true/false positives)"
echo "     - Re-run this script to incrementally improve the model"
echo ""
