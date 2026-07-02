#!/usr/bin/env python3
"""
PacketYeeter Model Evaluation Script

Evaluates ML model performance on labeled test data and tracks improvement over time.
Useful for comparing models before/after retraining.

Usage:
    # Evaluate current model
    python3 scripts/evaluate_model.py --model /var/lib/packetyeeter/model.onnx

    # Compare two models
    python3 scripts/evaluate_model.py --model /var/lib/packetyeeter/model.onnx --baseline /var/lib/packetyeeter/model_old.onnx

    # Use specific test data
    python3 scripts/evaluate_model.py --model model.onnx --test-data test_set.jsonl
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Dict, Tuple

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    classification_report,
    roc_auc_score,
    roc_curve,
)

# Try to import ONNX runtime for .onnx models
try:
    import onnxruntime as ort
    HAS_ONNX = True
except ImportError:
    HAS_ONNX = False
    print("Warning: onnxruntime not installed. Cannot test .onnx models")
    print("Install with: pip install onnxruntime")

# Try to import joblib for .pkl models
try:
    import joblib
    HAS_JOBLIB = True
except ImportError:
    HAS_JOBLIB = False


def load_model(model_path: str):
    """Load model from file (supports .onnx, .pkl, .json)."""
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
        # XGBoost native format
        try:
            import xgboost as xgb
            model = xgb.Booster()
            model.load_model(model_path)
            return ('xgboost', model)
        except ImportError:
            raise ImportError("xgboost required for .json models")
    
    else:
        raise ValueError(f"Unsupported model format: {model_path}")


def load_test_data(data_path: str) -> pd.DataFrame:
    """Load test data from JSONL file."""
    data = []
    with open(data_path, 'r') as f:
        for line in f:
            if line.strip():
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    
    if not data:
        raise ValueError(f"No valid data in {data_path}")
    
    df = pd.DataFrame(data)
    
    # Filter to bot/human labels only
    df = df[df['label'].isin(['bot', 'human'])]
    
    print(f"Loaded {len(df)} test samples")
    print(f"  Bot samples: {(df['label'] == 'bot').sum()}")
    print(f"  Human samples: {(df['label'] == 'human').sum()}")
    
    return df


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract features from test data (must match training exactly)."""
    # Import from train_model.py would be ideal, but we'll duplicate for now
    features = []
    
    for idx, row in df.iterrows():
        signal_breakdown = row.get('signal_breakdown', {})
        if not isinstance(signal_breakdown, dict):
            signal_breakdown = {}
        
        source_breakdown = row.get('source_breakdown', {})
        if not isinstance(source_breakdown, dict):
            source_breakdown = {}
        
        signal_count = row.get('signal_count', 0)
        time_span = row.get('time_span', 0)
        signal_rate = signal_count / (time_span / 60.0) if time_span > 0 else float(signal_count)
        
        feat = {
            'signal_count': signal_count,
            'signal_rate': signal_rate,
            'signal_rate_dup': signal_rate,
        }
        
        # Signal types (16 features)
        signal_types = [
            'high_frequency', 'path_seq_ids', 'missing_accept_language',
            'clock_skew_anomaly', 'entropy_low', 'high_threat_score', 'ua_suspicious',
            'missing_ja4h', 'incomplete_handshake', 'bad_flags', 'connection_pattern',
            'timing_pattern', 'proxy_lag', 'icmp_flood', 'udp_flood', 'syn_flood'
        ]
        for sig_type in signal_types:
            feat[f'sig_{sig_type}'] = signal_breakdown.get(sig_type, 0)
        
        # Source breakdown (5 features)
        sources = ['spoe', 'tcp', 'udp', 'icmp', 'fingerprint']
        for source in sources:
            feat[f'source_{source}'] = source_breakdown.get(source, 0)
        
        # Derived features (5 features)
        feat['http_signals'] = (
            signal_breakdown.get('high_frequency', 0) +
            signal_breakdown.get('missing_accept_language', 0) +
            signal_breakdown.get('ua_suspicious', 0)
        )
        feat['tcp_signals'] = (
            signal_breakdown.get('incomplete_handshake', 0) +
            signal_breakdown.get('bad_flags', 0) +
            signal_breakdown.get('connection_pattern', 0)
        )
        feat['ddos_signals'] = (
            signal_breakdown.get('icmp_flood', 0) +
            signal_breakdown.get('udp_flood', 0) +
            signal_breakdown.get('syn_flood', 0)
        )
        feat['scraper_signals'] = (
            signal_breakdown.get('path_seq_ids', 0) +
            signal_breakdown.get('missing_accept_language', 0)
        )
        
        # Threat intel + behavioral + temporal (12 features)
        feat['threat_score'] = float(row.get('threat_score', 0.0)) if not pd.isna(row.get('threat_score')) else 0.0
        feat['is_known_scanner'] = int(bool(row.get('is_known_scanner', False))) if not pd.isna(row.get('is_known_scanner')) else 0
        feat['is_cloud'] = int(bool(row.get('is_cloud', False))) if not pd.isna(row.get('is_cloud')) else 0
        feat['is_tor'] = int(bool(row.get('is_tor', False))) if not pd.isna(row.get('is_tor')) else 0
        feat['is_vpn'] = int(bool(row.get('is_vpn', False))) if not pd.isna(row.get('is_vpn')) else 0
        feat['open_ports'] = int(row.get('open_ports', 0)) if not pd.isna(row.get('open_ports')) else 0
        feat['reputation_score'] = float(row.get('reputation_score', 0.0)) if not pd.isna(row.get('reputation_score')) else 0.0
        feat['detection_history'] = int(row.get('detection_history', 0)) if not pd.isna(row.get('detection_history')) else 0
        feat['request_rate'] = float(row.get('request_rate', 0.0)) if not pd.isna(row.get('request_rate')) else 0.0
        feat['time_of_day'] = int(row.get('time_of_day', 12)) if not pd.isna(row.get('time_of_day')) else 12
        feat['day_of_week'] = int(row.get('day_of_week', 0)) if not pd.isna(row.get('day_of_week')) else 0
        feat['is_bursty'] = int(bool(row.get('is_bursty', False))) if not pd.isna(row.get('is_bursty')) else 0
        
        features.append(feat)
    
    return pd.DataFrame(features)


def predict(model_info: Tuple, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """Make predictions with model. Returns (predictions, probabilities)."""
    model_type, model = model_info
    
    if model_type == 'onnx':
        input_name = model.get_inputs()[0].name
        output = model.run(None, {input_name: X.astype(np.float32)})
        
        # ONNX output format: [label, {probabilities}]
        if len(output) == 2:
            predictions = output[0].flatten()
            # Probabilities are in format {0: prob_class0, 1: prob_class1}
            probs = output[1]
            # Extract probability of positive class (1 = bot)
            if isinstance(probs, list):
                prob_positive = np.array([p[1] if 1 in p else 0.5 for p in probs])
            else:
                prob_positive = probs[:, 1] if probs.shape[1] > 1 else probs.flatten()
        else:
            predictions = output[0].flatten()
            prob_positive = predictions  # Use predictions as proxy
        
        return predictions, prob_positive
    
    elif model_type == 'sklearn':
        predictions = model.predict(X)
        prob_positive = model.predict_proba(X)[:, 1] if hasattr(model, 'predict_proba') else predictions
        return predictions, prob_positive
    
    elif model_type == 'xgboost':
        import xgboost as xgb
        dmatrix = xgb.DMatrix(X)
        prob_positive = model.predict(dmatrix)
        predictions = (prob_positive > 0.5).astype(int)
        return predictions, prob_positive
    
    else:
        raise ValueError(f"Unknown model type: {model_type}")


def evaluate_model(model_path: str, test_data_path: str, model_name: str = "Model"):
    """Evaluate model and return metrics."""
    print(f"\n{'='*80}")
    print(f"Evaluating: {model_name}")
    print(f"{'='*80}\n")
    
    # Load model
    print(f"Loading model from {model_path}...")
    model_info = load_model(model_path)
    print(f"✓ Loaded {model_info[0]} model")
    
    # Load test data
    print(f"\nLoading test data from {test_data_path}...")
    df = load_test_data(test_data_path)
    
    if len(df) < 20:
        print(f"\n⚠️  Warning: Only {len(df)} test samples. Need at least 20 for reliable evaluation.")
    
    # Extract features
    X = extract_features(df)
    y_true = (df['label'] == 'bot').astype(int).values
    
    # Make predictions
    print(f"\nRunning predictions on {len(X)} samples...")
    y_pred, y_prob = predict(model_info, X.values)
    
    # Calculate metrics
    accuracy = accuracy_score(y_true, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary')
    
    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    # False positive rate (critical for production)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    
    # AUC if we have probabilities
    try:
        auc = roc_auc_score(y_true, y_prob)
    except:
        auc = None
    
    # Print results
    print(f"\n{'='*80}")
    print(f"📊 Results for {model_name}")
    print(f"{'='*80}\n")
    
    print(f"Overall Metrics:")
    print(f"  Accuracy:  {accuracy*100:6.2f}%")
    print(f"  Precision: {precision*100:6.2f}%  (of predicted bots, how many are real bots)")
    print(f"  Recall:    {recall*100:6.2f}%  (of real bots, how many did we catch)")
    print(f"  F1 Score:  {f1*100:6.2f}%  (harmonic mean of precision & recall)")
    if auc:
        print(f"  AUC-ROC:   {auc*100:6.2f}%  (overall discriminative ability)")
    
    print(f"\nConfusion Matrix:")
    print(f"                    Predicted")
    print(f"                Human    Bot")
    print(f"  Actual Human    {tn:4d}   {fp:4d}   (FP Rate: {fpr*100:.2f}%)")
    print(f"         Bot      {fn:4d}   {tp:4d}")
    
    print(f"\nProduction Impact:")
    print(f"  ✓ True Positives:  {tp:4d}  (correctly blocked bots)")
    print(f"  ✗ False Positives: {fp:4d}  (legitimate users incorrectly blocked)")
    print(f"  ✗ False Negatives: {fn:4d}  (bots that got through)")
    print(f"  ✓ True Negatives:  {tn:4d}  (legitimate users correctly allowed)")
    
    # False positive rate warning
    if fpr > 0.02:  # 2% threshold
        print(f"\n⚠️  WARNING: False positive rate is {fpr*100:.2f}% (target: <1%)")
        print(f"   This means {fpr*100:.2f}% of legitimate traffic would be blocked!")
    elif fpr > 0.01:
        print(f"\n⚠️  Caution: False positive rate is {fpr*100:.2f}% (target: <1%)")
    else:
        print(f"\n✓ False positive rate is good: {fpr*100:.2f}% (target: <1%)")
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'fpr': fpr,
        'auc': auc,
        'tp': tp,
        'fp': fp,
        'tn': tn,
        'fn': fn,
    }


def compare_models(baseline_metrics: Dict, new_metrics: Dict):
    """Compare two models and show improvement."""
    print(f"\n{'='*80}")
    print(f"📈 Model Comparison: Baseline vs New Model")
    print(f"{'='*80}\n")
    
    metrics = ['accuracy', 'precision', 'recall', 'f1', 'fpr', 'auc']
    
    print(f"{'Metric':<15} {'Baseline':>10} {'New Model':>10} {'Change':>10}")
    print(f"{'-'*50}")
    
    for metric in metrics:
        baseline_val = baseline_metrics.get(metric)
        new_val = new_metrics.get(metric)
        
        if baseline_val is None or new_val is None:
            continue
        
        # For FPR, lower is better
        if metric == 'fpr':
            change = baseline_val - new_val  # Positive change = improvement
            symbol = '↓' if change > 0 else '↑' if change < 0 else '='
        else:
            change = new_val - baseline_val
            symbol = '↑' if change > 0 else '↓' if change < 0 else '='
        
        print(f"{metric.upper():<15} {baseline_val*100:9.2f}% {new_val*100:9.2f}% {symbol} {abs(change)*100:6.2f}%")
    
    # Overall assessment
    print(f"\n{'='*80}")
    
    improvements = 0
    degradations = 0
    
    if new_metrics['f1'] > baseline_metrics['f1']:
        improvements += 1
    elif new_metrics['f1'] < baseline_metrics['f1']:
        degradations += 1
    
    if new_metrics['fpr'] < baseline_metrics['fpr']:
        improvements += 1
    elif new_metrics['fpr'] > baseline_metrics['fpr']:
        degradations += 1
    
    if improvements > degradations:
        print("✅ NEW MODEL IS BETTER")
        print(f"   Deploy this model to production!")
    elif degradations > improvements:
        print("⚠️  NEW MODEL IS WORSE")
        print(f"   Keep using the baseline model and collect more training data")
    else:
        print("📊 MODELS ARE SIMILAR")
        print(f"   No significant improvement. Consider:")
        print(f"   - Collecting more diverse training data")
        print(f"   - Balancing the dataset better")
        print(f"   - Adding more features")


def main():
    parser = argparse.ArgumentParser(description="Evaluate PacketYeeter ML model")
    parser.add_argument('--model', required=True, help='Path to model to evaluate (.onnx, .pkl, .json)')
    parser.add_argument('--baseline', help='Path to baseline model for comparison')
    parser.add_argument('--test-data', help='Path to test data (JSONL). If not provided, will use 20%% of combined dataset')
    
    args = parser.parse_args()
    
    # Determine test data path
    if args.test_data:
        test_data_path = args.test_data
    else:
        # Use combined training data (will split)
        default_paths = [
            '/var/lib/packetyeeter/combined_training.jsonl',
            '/var/lib/packetyeeter/training_data.jsonl',
            '/var/lib/packetyeeter/labeled_dataset.jsonl',
        ]
        test_data_path = None
        for path in default_paths:
            if os.path.exists(path):
                test_data_path = path
                break
        
        if not test_data_path:
            print("Error: No test data found. Specify --test-data or ensure training data exists.")
            sys.exit(1)
        
        print(f"Using test data from: {test_data_path}")
    
    # Evaluate main model
    new_metrics = evaluate_model(args.model, test_data_path, model_name="New Model")
    
    # Evaluate baseline if provided
    if args.baseline:
        baseline_metrics = evaluate_model(args.baseline, test_data_path, model_name="Baseline Model")
        compare_models(baseline_metrics, new_metrics)
    
    print(f"\n{'='*80}")
    print("Evaluation complete!")
    print(f"{'='*80}\n")


if __name__ == '__main__':
    main()
