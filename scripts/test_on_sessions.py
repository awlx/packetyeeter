#!/usr/bin/env python3
"""
Test ML Model on Recorded Sessions

Replays session recordings through the model to see how it would classify them
compared to the original detections. Useful for:
- Seeing if retrained model makes different decisions
- Finding false positives the new model would fix
- Understanding model evolution

Usage:
    # Test current model on all sessions
    python3 scripts/test_on_sessions.py --model /var/lib/packetyeeter/model.onnx

    # Compare two models on same sessions
    python3 scripts/test_on_sessions.py \
        --model /var/lib/packetyeeter/model.onnx \
        --baseline /var/lib/packetyeeter/model_old.onnx

    # Test on specific sessions
    python3 scripts/test_on_sessions.py \
        --model model.onnx \
        --sessions /var/cache/packetyeeter/sessions/
"""

import argparse
import json
import os
import sys
import glob
from pathlib import Path
from typing import List, Dict, Tuple
from collections import defaultdict

import numpy as np
import pandas as pd

# Try to import ONNX runtime
try:
    import onnxruntime as ort
    HAS_ONNX = True
except ImportError:
    HAS_ONNX = False
    print("Warning: onnxruntime not installed. Install with: pip install onnxruntime")

try:
    import joblib
    HAS_JOBLIB = True
except ImportError:
    HAS_JOBLIB = False


def load_model(model_path: str):
    """Load model from file."""
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found: {model_path}")
    
    if model_path.endswith('.onnx'):
        if not HAS_ONNX:
            raise ImportError("onnxruntime required for .onnx models")
        session = ort.InferenceSession(model_path)
        return ('onnx', session)
    
    elif model_path.endswith('.pkl'):
        if not HAS_JOBLIB:
            raise ImportError("joblib required for .pkl models")
        model = joblib.load(model_path)
        return ('sklearn', model)
    
    elif model_path.endswith('.json'):
        try:
            import xgboost as xgb
            model = xgb.Booster()
            model.load_model(model_path)
            return ('xgboost', model)
        except ImportError:
            raise ImportError("xgboost required for .json models")
    
    else:
        raise ValueError(f"Unsupported model format: {model_path}")


def load_sessions(sessions_dir: str) -> List[Dict]:
    """Load all session recordings."""
    sessions_dir = Path(sessions_dir)
    
    if not sessions_dir.exists():
        raise FileNotFoundError(f"Sessions directory not found: {sessions_dir}")
    
    pattern = str(sessions_dir / "recording-*.jsonl")
    files = glob.glob(pattern)
    
    if not files:
        raise ValueError(f"No session recordings found in {sessions_dir}")
    
    print(f"Loading {len(files)} session files...")
    
    sessions = []
    for filepath in sorted(files):
        with open(filepath, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        session = json.loads(line)
                        sessions.append(session)
                    except json.JSONDecodeError:
                        continue
    
    print(f"✓ Loaded {len(sessions)} sessions")
    return sessions


def extract_features_from_session(session: Dict) -> np.ndarray:
    """Extract features from a session recording (from Detection field)."""
    detection = session.get('Detection', {})
    
    signal_breakdown = detection.get('signal_breakdown', {})
    if not isinstance(signal_breakdown, dict):
        signal_breakdown = {}
    
    source_breakdown = detection.get('source_breakdown', {})
    if not isinstance(source_breakdown, dict):
        source_breakdown = {}
    
    signal_count = detection.get('signal_count', 0)
    time_span = detection.get('time_span', 0)
    signal_rate = signal_count / (time_span / 60.0) if time_span > 0 else float(signal_count)
    
    # Build feature vector (must match training exactly - 41 features)
    features = [
        signal_count,
        signal_rate,
        signal_rate,  # signal_rate_dup
    ]
    
    # Signal types (16)
    signal_types = [
        'high_frequency', 'path_seq_ids', 'missing_accept_language',
        'clock_skew_anomaly', 'entropy_low', 'high_threat_score', 'ua_suspicious',
        'missing_ja4h', 'incomplete_handshake', 'bad_flags', 'connection_pattern',
        'timing_pattern', 'proxy_lag', 'icmp_flood', 'udp_flood', 'syn_flood'
    ]
    for sig_type in signal_types:
        features.append(signal_breakdown.get(sig_type, 0))
    
    # Source breakdown (5)
    sources = ['spoe', 'tcp', 'udp', 'icmp', 'fingerprint']
    for source in sources:
        features.append(source_breakdown.get(source, 0))
    
    # Derived features (5) - MUST match training exactly!
    total_signals = sum(signal_breakdown.values()) if signal_breakdown else 1
    total_signals = max(total_signals, 1)
    
    # Signal diversity
    signal_types_with_counts = [v for v in signal_breakdown.values() if v > 0]
    sig_diversity = len(signal_types_with_counts) / 16.0 if signal_breakdown else 0
    features.append(sig_diversity)
    
    # High frequency ratio
    high_freq_ratio = signal_breakdown.get('high_frequency', 0) / total_signals
    features.append(high_freq_ratio)
    
    # Enumeration ratio
    enum_ratio = signal_breakdown.get('path_seq_ids', 0) / total_signals
    features.append(enum_ratio)
    
    # DDoS signals
    ddos_signals = (
        signal_breakdown.get('icmp_flood', 0) +
        signal_breakdown.get('udp_flood', 0) +
        signal_breakdown.get('syn_flood', 0)
    )
    features.append(ddos_signals)
    
    # Scraper signals
    scraper_signals = (
        signal_breakdown.get('path_seq_ids', 0) +
        signal_breakdown.get('missing_accept_language', 0)
    )
    features.append(scraper_signals)
    
    # Threat intel + behavioral + temporal (12)
    features.extend([
        float(detection.get('threat_score', 0.0)),
        int(bool(detection.get('is_known_scanner', False))),
        int(bool(detection.get('is_cloud', False))),
        int(bool(detection.get('is_tor', False))),
        int(bool(detection.get('is_vpn', False))),
        int(detection.get('open_ports', 0)),
        float(detection.get('reputation_score', 0.0)),
        int(detection.get('detection_history', 0)),
        float(detection.get('request_rate', 0.0)),
        int(detection.get('time_of_day', 12)),
        int(detection.get('day_of_week', 0)),
        int(bool(detection.get('is_bursty', False))),
    ])
    
    return np.array(features, dtype=np.float32)


def predict(model_info: Tuple, X: np.ndarray) -> Tuple[int, float]:
    """Make prediction. Returns (prediction, probability)."""
    model_type, model = model_info
    
    # Reshape for single prediction
    X = X.reshape(1, -1)
    
    if model_type == 'onnx':
        input_name = model.get_inputs()[0].name
        output = model.run(None, {input_name: X})
        
        if len(output) == 2:
            prediction = int(output[0][0])
            probs = output[1][0]
            
            # Handle different ONNX probability formats
            if isinstance(probs, dict):
                # Dictionary format: {0: prob_class0, 1: prob_class1}
                probability = float(probs.get(1, probs.get('1', 0.5)))
            elif isinstance(probs, (list, np.ndarray)):
                # Array format: [prob_class0, prob_class1]
                if len(probs) > 1:
                    probability = float(probs[1])
                else:
                    probability = float(probs[0])
            else:
                probability = 0.5
        else:
            prediction = int(output[0][0])
            probability = float(prediction)
        
        return prediction, probability
    
    elif model_type == 'sklearn':
        prediction = int(model.predict(X)[0])
        probability = float(model.predict_proba(X)[0, 1]) if hasattr(model, 'predict_proba') else float(prediction)
        return prediction, probability
    
    elif model_type == 'xgboost':
        import xgboost as xgb
        dmatrix = xgb.DMatrix(X)
        probability = float(model.predict(dmatrix)[0])
        prediction = 1 if probability > 0.5 else 0
        return prediction, probability
    
    else:
        raise ValueError(f"Unknown model type: {model_type}")


def test_sessions(model_path: str, sessions: List[Dict], model_name: str = "Model"):
    """Test model on sessions and compare with original detections."""
    print(f"\n{'='*80}")
    print(f"Testing: {model_name}")
    print(f"{'='*80}\n")
    
    model_info = load_model(model_path)
    print(f"✓ Loaded {model_info[0]} model\n")
    
    results = {
        'total': 0,
        'with_label': 0,
        'correct_vs_label': 0,
        'agrees_with_original': 0,
        'disagrees_with_original': 0,
        'would_fix_fp': 0,  # Model says human, original blocked, label says human
        'would_create_fp': 0,  # Model says bot, original allowed, label says human
        'would_catch_fn': 0,  # Model says bot, original allowed, label says bot
        'would_miss_bot': 0,  # Model says human, original blocked, label says bot
        'disagreements': [],
    }
    
    print("Processing sessions...")
    for session in sessions:
        results['total'] += 1
        
        # Extract features
        try:
            features = extract_features_from_session(session)
        except Exception as e:
            print(f"Warning: Failed to extract features from session {session.get('SessionID')}: {e}")
            continue
        
        # Get model prediction
        prediction, probability = predict(model_info, features)
        model_says_bot = (prediction == 1)
        
        # Get original detection decision
        detection = session.get('Detection', {})
        original_blocked = detection.get('would_block', False)
        original_confidence = detection.get('confidence', 0.0)
        
        # Get ground truth label (if available)
        label = session.get('Label', '')
        label_says_bot = label in ['tp', 'fn', 'bot']
        label_says_human = label in ['fp', 'tn', 'human']
        
        # Compare with original detection
        if model_says_bot == original_blocked:
            results['agrees_with_original'] += 1
        else:
            results['disagrees_with_original'] += 1
            
            # Store disagreement details
            results['disagreements'].append({
                'ip': session.get('IP'),
                'session_id': session.get('SessionID'),
                'model_says': 'BOT' if model_says_bot else 'HUMAN',
                'model_prob': probability,
                'original_says': 'BLOCK' if original_blocked else 'ALLOW',
                'original_conf': original_confidence,
                'label': label,
                'category': detection.get('bot_category'),
            })
        
        # If we have ground truth label, evaluate accuracy
        if label_says_bot or label_says_human:
            results['with_label'] += 1
            
            # Check if model is correct vs label
            if (model_says_bot and label_says_bot) or (not model_says_bot and label_says_human):
                results['correct_vs_label'] += 1
            
            # Analyze specific scenarios
            if not model_says_bot and original_blocked and label_says_human:
                results['would_fix_fp'] += 1  # Model fixes a false positive
            elif model_says_bot and not original_blocked and label_says_human:
                results['would_create_fp'] += 1  # Model creates a false positive
            elif model_says_bot and not original_blocked and label_says_bot:
                results['would_catch_fn'] += 1  # Model catches a false negative
            elif not model_says_bot and original_blocked and label_says_bot:
                results['would_miss_bot'] += 1  # Model misses a bot
    
    return results


def print_results(results: Dict, model_name: str):
    """Print test results."""
    print(f"\n{'='*80}")
    print(f"📊 Results for {model_name}")
    print(f"{'='*80}\n")
    
    print(f"Sessions Analyzed: {results['total']}")
    print(f"  With Labels: {results['with_label']}")
    print(f"  Without Labels: {results['total'] - results['with_label']}")
    
    print(f"\nAgreement with Original Detections:")
    print(f"  Agrees:    {results['agrees_with_original']:4d} ({results['agrees_with_original']/results['total']*100:5.1f}%)")
    print(f"  Disagrees: {results['disagrees_with_original']:4d} ({results['disagrees_with_original']/results['total']*100:5.1f}%)")
    
    if results['with_label'] > 0:
        accuracy = results['correct_vs_label'] / results['with_label']
        print(f"\nAccuracy vs Ground Truth Labels:")
        print(f"  Correct: {results['correct_vs_label']}/{results['with_label']} ({accuracy*100:.1f}%)")
        
        print(f"\nImpact Analysis (based on labeled sessions):")
        if results['would_fix_fp'] > 0:
            print(f"  ✅ Would Fix False Positives: {results['would_fix_fp']}")
            print(f"     (Model correctly identifies as human, original blocked)")
        if results['would_create_fp'] > 0:
            print(f"  ⚠️  Would Create False Positives: {results['would_create_fp']}")
            print(f"     (Model incorrectly says bot, original allowed)")
        if results['would_catch_fn'] > 0:
            print(f"  ✅ Would Catch False Negatives: {results['would_catch_fn']}")
            print(f"     (Model catches bots that original missed)")
        if results['would_miss_bot'] > 0:
            print(f"  ⚠️  Would Miss Bots: {results['would_miss_bot']}")
            print(f"     (Model misses bots that original caught)")
    
    # Show sample disagreements
    if results['disagreements'] and len(results['disagreements']) <= 20:
        print(f"\n{'='*80}")
        print(f"Disagreements with Original Detection:")
        print(f"{'='*80}\n")
        
        for d in results['disagreements'][:10]:
            print(f"IP: {d['ip']}")
            print(f"  Model:    {d['model_says']} (prob: {d['model_prob']:.3f})")
            print(f"  Original: {d['original_says']} (conf: {d['original_conf']:.3f}, cat: {d['category']})")
            if d['label']:
                print(f"  Label:    {d['label']} (ground truth)")
            print()


def compare_models(baseline_results: Dict, new_results: Dict):
    """Compare two models on same sessions."""
    print(f"\n{'='*80}")
    print(f"📈 Model Comparison")
    print(f"{'='*80}\n")
    
    print(f"{'Metric':<35} {'Baseline':>10} {'New':>10} {'Change':>10}")
    print(f"{'-'*70}")
    
    # Agreement rate with original
    baseline_agree_pct = baseline_results['agrees_with_original'] / baseline_results['total'] * 100
    new_agree_pct = new_results['agrees_with_original'] / new_results['total'] * 100
    change = new_agree_pct - baseline_agree_pct
    print(f"{'Agreement with Original':<35} {baseline_agree_pct:9.1f}% {new_agree_pct:9.1f}% {change:+9.1f}%")
    
    # Accuracy on labeled data
    if baseline_results['with_label'] > 0 and new_results['with_label'] > 0:
        baseline_acc = baseline_results['correct_vs_label'] / baseline_results['with_label'] * 100
        new_acc = new_results['correct_vs_label'] / new_results['with_label'] * 100
        change = new_acc - baseline_acc
        symbol = '↑' if change > 0 else '↓' if change < 0 else '='
        print(f"{'Accuracy vs Labels':<35} {baseline_acc:9.1f}% {new_acc:9.1f}% {symbol} {abs(change):7.1f}%")
        
        # False positive improvements
        baseline_fp = baseline_results['would_create_fp']
        new_fp = new_results['would_create_fp']
        baseline_fix_fp = baseline_results['would_fix_fp']
        new_fix_fp = new_results['would_fix_fp']
        
        print(f"\n{'Impact':<35} {'Baseline':>10} {'New':>10}")
        print(f"{'-'*70}")
        print(f"{'Would Fix False Positives':<35} {baseline_fix_fp:10d} {new_fix_fp:10d}")
        print(f"{'Would Create False Positives':<35} {baseline_fp:10d} {new_fp:10d}")
        print(f"{'Would Catch False Negatives':<35} {baseline_results['would_catch_fn']:10d} {new_results['would_catch_fn']:10d}")
        print(f"{'Would Miss Bots':<35} {baseline_results['would_miss_bot']:10d} {new_results['would_miss_bot']:10d}")
        
        # Overall assessment
        print(f"\n{'='*80}")
        if new_acc > baseline_acc and new_fp <= baseline_fp:
            print("✅ NEW MODEL IS BETTER")
            print("   More accurate and doesn't increase false positives")
        elif new_acc > baseline_acc:
            print("📊 NEW MODEL IS MORE ACCURATE")
            print(f"   But watch out: creates {new_fp} false positives vs {baseline_fp} baseline")
        else:
            print("⚠️  NEW MODEL NEEDS IMPROVEMENT")
            print("   Consider collecting more training data")


def main():
    parser = argparse.ArgumentParser(description="Test ML model on recorded sessions")
    parser.add_argument('--model', required=True, help='Path to model to test')
    parser.add_argument('--baseline', help='Path to baseline model for comparison')
    parser.add_argument('--sessions', default='/var/cache/packetyeeter/sessions',
                        help='Path to sessions directory')
    
    args = parser.parse_args()
    
    # Load sessions
    sessions = load_sessions(args.sessions)
    
    if len(sessions) == 0:
        print("Error: No sessions found")
        sys.exit(1)
    
    # Test new model
    new_results = test_sessions(args.model, sessions, model_name="New Model")
    print_results(new_results, "New Model")
    
    # Test baseline if provided
    if args.baseline:
        baseline_results = test_sessions(args.baseline, sessions, model_name="Baseline Model")
        print_results(baseline_results, "Baseline Model")
        compare_models(baseline_results, new_results)
    
    print(f"\n{'='*80}")
    print("Testing complete!")
    print(f"{'='*80}\n")


if __name__ == '__main__':
    main()
