#!/bin/bash
# Quick Deploy Script - ONNX Feature Alignment Patches
# Run this on production server after pulling latest code

set -e

echo "=================================================="
echo "ONNX Feature Alignment - Production Deploy"
echo "=================================================="

# Configuration
DATASET="/var/lib/packetyeeter/labeled_dataset.jsonl"
MODEL_DIR="/var/lib/packetyeeter"
MODEL_NEW="$MODEL_DIR/model_v2.onnx"
MODEL_PROD="$MODEL_DIR/model.onnx"
MODEL_BACKUP="$MODEL_DIR/model.onnx.backup.$(date +%Y%m%d_%H%M%S)"

# Check prerequisites
if [ ! -f "$DATASET" ]; then
    echo "❌ Error: Dataset not found: $DATASET"
    echo "   Have you labeled any detections in the UI?"
    exit 1
fi

SAMPLE_COUNT=$(wc -l < "$DATASET")
if [ "$SAMPLE_COUNT" -lt 50 ]; then
    echo "⚠️  Warning: Only $SAMPLE_COUNT labeled samples found"
    echo "   Minimum 50 recommended, 200+ ideal"
    read -p "   Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo ""
echo "✅ Found $SAMPLE_COUNT labeled samples"

# Step 1: Validate features
echo ""
echo "Step 1: Validating feature structure..."
/tmp/venv/bin/python3 scripts/validate_features.py --input "$DATASET"

if [ $? -ne 0 ]; then
    echo "❌ Feature validation failed"
    exit 1
fi

# Step 2: Train new model (with warm start from existing model)
echo ""
echo "Step 2: Training new model with 41 features..."
if [ -f "$MODEL_PROD" ]; then
    echo "   Using existing model as base for incremental learning"
    /tmp/venv/bin/python3 scripts/train_model.py \
        --input "$DATASET" \
        --output "$MODEL_NEW" \
        --model xgb \
        --test-size 0.2 \
        --base-model "$MODEL_PROD"
else
    echo "   No existing model found, training from scratch"
    /tmp/venv/bin/python3 scripts/train_model.py \
        --input "$DATASET" \
        --output "$MODEL_NEW" \
        --model xgb \
        --test-size 0.2
fi

if [ $? -ne 0 ]; then
    echo "❌ Model training failed"
    exit 1
fi

echo "✅ Model trained: $MODEL_NEW"

# Step 3: Backup old models (both ONNX and native XGBoost)
if [ -f "$MODEL_PROD" ]; then
    echo ""
    echo "Step 3: Backing up existing models..."
    cp "$MODEL_PROD" "$MODEL_BACKUP"
    echo "✅ Backup saved: $MODEL_BACKUP"
    
    # Also backup native XGBoost model if it exists
    MODEL_JSON="${MODEL_PROD%.onnx}.json"
    if [ -f "$MODEL_JSON" ]; then
        cp "$MODEL_JSON" "${MODEL_BACKUP%.onnx}.json"
        echo "✅ XGBoost native backup saved: ${MODEL_BACKUP%.onnx}.json"
    fi
else
    echo ""
    echo "Step 3: No existing model to backup"
fi

# Step 4: Deploy new models (both formats)
echo ""
echo "Step 4: Deploying new models..."
cp "$MODEL_NEW" "$MODEL_PROD"
echo "✅ ONNX model deployed: $MODEL_PROD"

# Deploy native XGBoost format if it exists (for future incremental training)
MODEL_NEW_JSON="${MODEL_NEW%.onnx}.json"
MODEL_PROD_JSON="${MODEL_PROD%.onnx}.json"
if [ -f "$MODEL_NEW_JSON" ]; then
    cp "$MODEL_NEW_JSON" "$MODEL_PROD_JSON"
    echo "✅ XGBoost native model deployed: $MODEL_PROD_JSON"
fi

# Step 5: Restart analyzer
echo ""
echo "Step 5: Restarting analyzer service..."
sudo systemctl restart packetyeeter-analyzer

echo ""
echo "Waiting for service to start..."
sleep 5

# Step 6: Check status
echo ""
echo "Step 6: Verifying deployment..."

if ! sudo systemctl is-active --quiet packetyeeter-analyzer; then
    echo "❌ Service failed to start!"
    echo ""
    echo "Rolling back to previous model..."
    if [ -f "$MODEL_BACKUP" ]; then
        cp "$MODEL_BACKUP" "$MODEL_PROD"
        sudo systemctl restart packetyeeter-analyzer
        echo "⚠️  Rollback complete. Check logs:"
        echo "   sudo journalctl -u packetyeeter-analyzer -n 50"
    fi
    exit 1
fi

echo "✅ Service is running"

# Check for errors
echo ""
echo "Checking for feature errors..."
ERROR_COUNT=$(sudo journalctl -u packetyeeter-analyzer --since "2 minutes ago" | grep -c "CRITICAL.*Feature count mismatch" || true)

if [ "$ERROR_COUNT" -gt 0 ]; then
    echo "❌ Found $ERROR_COUNT feature count errors!"
    echo "   Model may be incompatible"
    echo ""
    echo "Recent errors:"
    sudo journalctl -u packetyeeter-analyzer --since "2 minutes ago" | grep "Feature count mismatch" | tail -5
    exit 1
else
    echo "✅ No feature count errors"
fi

# Show ML metrics
echo ""
echo "=================================================="
echo "✅ Deployment Complete!"
echo "=================================================="
echo ""
echo "Model Info:"
echo "  Location: $MODEL_PROD"
echo "  Features: 41"
echo "  Training samples: $SAMPLE_COUNT"
echo "  Backup: $MODEL_BACKUP"
echo ""
echo "Next Steps:"
echo "  1. Monitor logs: sudo journalctl -u packetyeeter-analyzer -f"
echo "  2. Check metrics: curl http://localhost:9092/api/ml/metrics | jq"
echo "  3. View detections: http://localhost:9092 (inspector UI)"
echo ""
echo "If issues occur, rollback with:"
echo "  sudo cp $MODEL_BACKUP $MODEL_PROD"
echo "  sudo cp ${MODEL_BACKUP%.onnx}.json ${MODEL_PROD%.onnx}.json"
echo "  sudo systemctl restart packetyeeter-analyzer"
