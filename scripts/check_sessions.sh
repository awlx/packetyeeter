#!/bin/bash
# Quick Reference: Session Recording & Incremental Training

echo "═══════════════════════════════════════════════════════════"
echo "  Session Recording & Incremental Training - Quick Guide"
echo "═══════════════════════════════════════════════════════════"

# Check session recordings
echo ""
echo "📁 Session Recordings:"
echo "   Location: /var/cache/packetyeeter/sessions/"
if [ -d /var/cache/packetyeeter/sessions/ ]; then
    SESSION_COUNT=$(find /var/cache/packetyeeter/sessions/ -name "*.jsonl" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}')
    FILE_COUNT=$(ls /var/cache/packetyeeter/sessions/*.jsonl 2>/dev/null | wc -l)
    echo "   Files: $FILE_COUNT"
    echo "   Total recordings: ${SESSION_COUNT:-0}"
else
    echo "   ⚠️  Directory not found - will be created on first recording"
fi

# Check labeled data
echo ""
echo "📊 Training Data:"
LABELED="/var/lib/packetyeeter/labeled_dataset.jsonl"
if [ -f "$LABELED" ]; then
    LABELED_COUNT=$(wc -l < "$LABELED")
    echo "   Manual labels: $LABELED_COUNT samples"
else
    echo "   ⚠️  No manual labels yet"
fi

# Check current model
echo ""
echo "🤖 Current Model:"
MODEL="/var/lib/packetyeeter/model.onnx"
MODEL_JSON="/var/lib/packetyeeter/model.json"
if [ -f "$MODEL" ]; then
    MODEL_SIZE=$(ls -lh "$MODEL" | awk '{print $5}')
    MODEL_DATE=$(ls -l "$MODEL" | awk '{print $6, $7, $8}')
    echo "   ONNX (inference): $MODEL"
    echo "   Size: $MODEL_SIZE"
    echo "   Date: $MODEL_DATE"
    
    if [ -f "$MODEL_JSON" ]; then
        JSON_SIZE=$(ls -lh "$MODEL_JSON" | awk '{print $5}')
        echo "   XGBoost (training): $MODEL_JSON"
        echo "   Size: $JSON_SIZE"
    else
        echo "   ⚠️  XGBoost native format not found (needed for incremental training)"
    fi
else
    echo "   ⚠️  No model deployed yet"
fi

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Common Commands"
echo "═══════════════════════════════════════════════════════════"

echo ""
echo "1️⃣  Convert sessions to training data:"
echo "   /tmp/venv/bin/python3 scripts/sessions_to_training.py --days 7"
echo ""

echo "2️⃣  Train with incremental learning:"
echo "   /tmp/venv/bin/python3 scripts/train_model.py \\"
echo "     --input /var/lib/packetyeeter/labeled_dataset.jsonl \\"
echo "     --base-model /var/lib/packetyeeter/model.onnx \\"
echo "     --output /tmp/model_new.onnx"
echo "   Note: Uses model.json for warm start, creates both .onnx and .json"
echo ""

echo "3️⃣  Deploy new model (with auto incremental training):"
echo "   sudo ./scripts/deploy_new_model.sh"
echo ""

echo "4️⃣  View latest sessions:"
echo "   tail -f /var/cache/packetyeeter/sessions/sessions_\$(date +%Y-%m-%d).jsonl | jq"
echo ""

echo "5️⃣  Check model metrics:"
echo "   curl http://localhost:9092/api/ml/metrics | jq"
echo ""

echo "═══════════════════════════════════════════════════════════"
echo "  Key Features"
echo "═══════════════════════════════════════════════════════════"

echo ""
echo "✅ Session Recording (Automatic):"
echo "   • Saves to: /var/cache/packetyeeter/sessions/sessions_YYYY-MM-DD.jsonl"
echo "   • Format: JSONL (one recording per line)"
echo "   • Trigger: Confidence > 0.5 or would block"
echo "   • Duration: 5 minutes post-detection"
echo "   • Storage: ~100 KB per recording"
echo ""

echo "✅ Incremental Training:"
echo "   • Preserves previous model weights"
echo "   • Adds 50 new estimators per training"
echo "   • Lower learning rate for fine-tuning"
echo "   • Cumulative improvement over time"
echo "   • Usage: --base-model <existing_model.onnx>"
echo "   • Dual format: .json (training) + .onnx (inference)"
echo ""

echo "═══════════════════════════════════════════════════════════"
echo "  Troubleshooting"
echo "═══════════════════════════════════════════════════════════"

echo ""
echo "❓ No sessions being saved?"
echo "   sudo journalctl -u packetyeeter-analyzer | grep -i 'session recording'"
echo "   sudo chown -R packetyeeter:packetyeeter /var/cache/packetyeeter/sessions/"
echo ""

echo "❓ Incremental training fails?"
echo "   # Check if base model is valid"json\")'"
echo "   # Note: Incremental training needs .json format, not .onnx
echo "   /tmp/venv/bin/python3 -c 'import xgboost as xgb; m = xgb.XGBClassifier(); m.load_model(\"/var/lib/packetyeeter/model.onnx\")'"
echo "   # If fails, train from scratch (no --base-model)"
echo ""

echo "❓ Model too large?"
echo "   # Reset to 100 trees monthly"
echo "   /tmp/venv/bin/python3 scripts/train_model.py --input dataset.jsonl --output model.onnx"
echo ""

echo "═══════════════════════════════════════════════════════════"

echo ""
echo "📚 Full documentation: INCREMENTAL_TRAINING.md"
echo ""
