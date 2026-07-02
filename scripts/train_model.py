#!/tmp/venv/bin/python3
"""
PacketYeeter ML Model Training Script

This script trains a machine learning model to detect bots/scrapers/DDoS attacks
using labeled detection data from the PacketYeeter system.

Usage:
    python train_model.py --input labeled_dataset.jsonl --output model.onnx

Requirements:
    pip install scikit-learn xgboost pandas numpy onnx skl2onnx onnxmltools
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_recall_fscore_support,
)
from sklearn.preprocessing import StandardScaler
import joblib

try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
    print("Warning: XGBoost not installed. Install with: pip install xgboost")

try:
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
    import onnxmltools
    from onnxmltools.convert.common.data_types import FloatTensorType as OnnxMLFloatTensorType
    HAS_ONNX = True
except ImportError:
    HAS_ONNX = False
    print("Warning: ONNX conversion not available. Install with: pip install onnx skl2onnx onnxmltools")


def load_labeled_data(filepath: str) -> pd.DataFrame:
    """Load labeled detections from JSONL file."""
    data = []
    
    with open(filepath, 'r') as f:
        for line in f:
            try:
                obj = json.loads(line.strip())
                data.append(obj)
            except json.JSONDecodeError as e:
                print(f"Warning: Failed to parse line: {e}")
                continue
    
    if not data:
        raise ValueError(f"No valid data found in {filepath}")
    
    print(f"Loaded {len(data)} labeled samples")
    return pd.DataFrame(data)


def load_session_data(filepath: str) -> pd.DataFrame:
    """Load session recordings and convert to training examples."""
    data = []
    
    with open(filepath, 'r') as f:
        for line in f:
            try:
                session = json.loads(line.strip())
                
                # Extract detection features
                det = session.get('Detection', {})
                
                # Add temporal features from session
                pre_events = session.get('PreEvents', [])
                post_events = session.get('PostEvents', [])
                duration = session.get('Duration', 0)
                
                # Calculate temporal features
                total_events = len(pre_events) + len(post_events)
                event_rate = total_events / (duration / 1e9 / 60) if duration > 0 else 0  # events per minute
                
                # Use explicit Label field from recording (tp/fp/tn/fn/bot/human/manual)
                # This is set by the user via the Inspector UI or feedback endpoints
                session_label = session.get('Label', '')
                
                # Map label to binary classification
                # tp (true positive), fn (false negative), bot = malicious
                # fp (false positive), tn (true negative), human, verified_bot = legitimate
                # manual/unknown = skip for training
                if session_label in ['tp', 'fn', 'bot']:
                    label = 'bot'
                elif session_label in ['fp', 'tn', 'human', 'verified_bot']:
                    label = 'human'
                else:
                    # Fallback to outcome-based label if no explicit label
                    outcome = session.get('Outcome', 'unknown')
                    if outcome in ['escalated', 'blocked']:
                        label = 'bot'
                    elif outcome in ['disappeared', 'allowed']:
                        label = 'human'
                    else:
                        continue  # Skip unknown/manual unlabeled sessions
                
                # Merge detection features with session context
                example = {
                    **det,
                    'post_event_count': len(post_events),
                    'event_rate': event_rate,
                    'session_duration_sec': duration / 1e9 if duration > 0 else 0,
                    'label': label
                }
                data.append(example)
                
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Warning: Failed to parse session: {e}")
                continue
    
    if not data:
        print("Warning: No valid session data found")
        return pd.DataFrame()
    
    print(f"Loaded {len(data)} session recordings")
    return pd.DataFrame(data)


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract feature vectors from labeled detections."""
    features = []
    
    for idx, row in df.iterrows():
        # Handle both dict and non-dict signal_breakdown (session data may differ)
        signal_breakdown = row.get('signal_breakdown', {})
        if not isinstance(signal_breakdown, dict):
            signal_breakdown = {}
        
        source_breakdown = row.get('source_breakdown', {})
        if not isinstance(source_breakdown, dict):
            source_breakdown = {}
        
        # Core features - MUST match pkg/ml/onnx.go featuresToTensor() exactly!
        signal_count = row.get('signal_count', 0)
        # Calculate signal_rate: signals per minute (if time_span available) or use signal_count as proxy
        time_span = row.get('time_span', 0)  # seconds
        signal_rate = signal_count / (time_span / 60.0) if time_span > 0 else float(signal_count)
        
        feat = {
            'signal_count': signal_count,
            'signal_rate': signal_rate,
            'signal_rate_dup': signal_rate,  # Go code duplicates signal_rate for backward compat
        }
        
        # Signal type features (one-hot encoding)
        # CRITICAL: These names MUST match the Go SignalType string output exactly!
        # See: pkg/analyzer/aidetection/types.go
        signal_types = [
            'high_frequency', 'path_seq_ids', 'missing_accept_language',
            'clock_skew_anomaly', 'entropy_low', 'high_threat_score', 'ua_suspicious',
            'missing_ja4h', 'incomplete_handshake', 'bad_flags', 'connection_pattern',
            'timing_pattern', 'proxy_lag', 'icmp_flood', 'udp_flood', 'syn_flood'
        ]
        
        for sig_type in signal_types:
            feat[f'sig_{sig_type}'] = signal_breakdown.get(sig_type, 0)
        
        # Source breakdown features
        # CRITICAL: These names MUST match the Go SourceType string output exactly!
        # See: pkg/analyzer/aidetection/types.go
        sources = ['spoe', 'tcp', 'udp', 'icmp', 'fingerprint']
        for source in sources:
            feat[f'source_{source}'] = source_breakdown.get(source, 0)
        
        # Derived features
        total_signals = sum(signal_breakdown.values()) if signal_breakdown else 1
        total_signals = max(total_signals, 1)  # Avoid division by zero
        feat['sig_diversity'] = len([v for v in signal_breakdown.values() if v > 0]) / len(signal_types) if signal_breakdown else 0
        feat['high_freq_ratio'] = signal_breakdown.get('high_frequency', 0) / total_signals
        feat['enum_ratio'] = signal_breakdown.get('path_seq_ids', 0) / total_signals
        feat['ddos_signals'] = (
            signal_breakdown.get('icmp_flood', 0) +
            signal_breakdown.get('udp_flood', 0) +
            signal_breakdown.get('syn_flood', 0)
        )
        feat['scraper_signals'] = (
            signal_breakdown.get('path_seq_ids', 0) +
            signal_breakdown.get('missing_accept_language', 0)
        )
        
        # Threat Intelligence features (collected at runtime from Shodan/threatintel)
        # Use pd.isna() to handle NaN values from missing JSON fields
        feat['threat_score'] = float(row.get('threat_score', 0.0)) if not pd.isna(row.get('threat_score')) else 0.0
        feat['is_known_scanner'] = int(bool(row.get('is_known_scanner', False))) if not pd.isna(row.get('is_known_scanner')) else 0
        feat['is_cloud'] = int(bool(row.get('is_cloud', False))) if not pd.isna(row.get('is_cloud')) else 0
        feat['is_tor'] = int(bool(row.get('is_tor', False))) if not pd.isna(row.get('is_tor')) else 0
        feat['is_vpn'] = int(bool(row.get('is_vpn', False))) if not pd.isna(row.get('is_vpn')) else 0
        feat['open_ports'] = int(row.get('open_ports', 0)) if not pd.isna(row.get('open_ports')) else 0
        
        # Behavioral features (from reputation and detection history)
        feat['reputation_score'] = float(row.get('reputation_score', 0.0)) if not pd.isna(row.get('reputation_score')) else 0.0
        feat['detection_history'] = int(row.get('detection_history', 0)) if not pd.isna(row.get('detection_history')) else 0
        feat['request_rate'] = float(row.get('request_rate', 0.0)) if not pd.isna(row.get('request_rate')) else 0.0
        
        # Temporal features
        feat['time_of_day'] = int(row.get('time_of_day', 12)) if not pd.isna(row.get('time_of_day')) else 12  # Default to noon
        feat['day_of_week'] = int(row.get('day_of_week', 0)) if not pd.isna(row.get('day_of_week')) else 0   # Default to Sunday
        feat['is_bursty'] = int(bool(row.get('is_bursty', False))) if not pd.isna(row.get('is_bursty')) else 0
        
        features.append(feat)
    
    return pd.DataFrame(features)


def prepare_dataset(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
    """Prepare features (X) and labels (y) for training."""
    # Extract features
    X_df = extract_features(df)
    
    # CRITICAL VALIDATION: Feature count must match runtime exactly
    # 3 (core) + 16 (signals) + 5 (sources) + 5 (derived) + 12 (threat_intel + behavioral + temporal) = 41
    expected_features = 41
    if X_df.shape[1] != expected_features:
        raise ValueError(f"Feature count mismatch! Expected {expected_features}, got {X_df.shape[1]}. "
                        f"This will break ONNX inference. Check extract_features() implementation.")
    
    # Create binary labels: 1 = malicious bot, 0 = legitimate (human or legitimate bot)
    # Note: "bot_legitimate" is treated as non-malicious (same as "human")
    y = (df['label'] == 'bot').astype(int).values
    
    print(f"\nFeature matrix shape: {X_df.shape}")
    print(f"Features: {list(X_df.columns)}")
    print(f"\nLabel distribution:")
    print(f"  Malicious Bots: {y.sum()} ({y.sum()/len(y)*100:.1f}%)")
    print(f"  Legitimate (Human + Legit Bots): {(1-y).sum()} ({(1-y).sum()/len(y)*100:.1f}%)")
    
    # Show breakdown if bot_legitimate labels exist
    if 'label' in df.columns:
        legit_bots = (df['label'] == 'bot_legitimate').sum()
        humans = (df['label'] == 'human').sum()
        if legit_bots > 0:
            print(f"    - Humans: {humans}")
            print(f"    - Legitimate Bots: {legit_bots}")
    
    return X_df.values, y


def train_random_forest(X_train, y_train, X_test, y_test) -> RandomForestClassifier:
    """Train a Random Forest classifier."""
    print("\n" + "="*80)
    print("Training Random Forest Classifier")
    print("="*80)
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='binary')
    
    print(f"\nTest Set Performance:")
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1 Score:  {f1:.4f}")
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    print(cm)
    
    print("\nClassification Report:")
    # Check if both classes are present in predictions
    unique_pred = np.unique(y_pred)
    if len(unique_pred) < 2:
        print("Warning: Model only predicting one class!")
        print(classification_report(y_test, y_pred, labels=[0, 1], target_names=['Human', 'Bot'], zero_division=0))
    else:
        print(classification_report(y_test, y_pred, target_names=['Human', 'Bot'], zero_division=0))
    
    # Feature importance
    print("\nTop 10 Most Important Features:")
    # Note: This requires feature names which we'll need to track
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1][:10]
    for i, idx in enumerate(indices):
        print(f"  {i+1}. Feature {idx}: {importances[idx]:.4f}")
    
    return model


def train_xgboost(X_train, y_train, X_test, y_test, base_model_path=None):
    """Train an XGBoost classifier with optional warm start from previous model."""
    if not HAS_XGBOOST:
        print("XGBoost not available, skipping...")
        return None
    
    print("\n" + "="*80)
    print("Training XGBoost Classifier")
    if base_model_path:
        print(f"Warm Start: Loading weights from {base_model_path}")
    print("="*80)
    
    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        random_state=42,
        eval_metric='logloss',
    )
    
    # Warm start from previous model if provided
    if base_model_path and os.path.exists(base_model_path):
        # Try to find native XGBoost format (.json) for warm start
        # ONNX files can't be loaded by XGBoost for training
        xgb_model_path = base_model_path.replace('.onnx', '.json')
        if not os.path.exists(xgb_model_path):
            print(f"⚠️  Warning: Native XGBoost model not found: {xgb_model_path}")
            print("   ONNX format can't be used for warm start (inference only)")
            print("   Training from scratch instead")
            model.fit(X_train, y_train)
        else:
            try:
                # Load previous model and continue training
                base_model = xgb.XGBClassifier()
                base_model.load_model(xgb_model_path)
                
                # Get number of estimators from booster
                booster = base_model.get_booster()
                num_boost_round = len(booster.get_dump())
                
                # Copy learned parameters
                model = xgb.XGBClassifier(
                    n_estimators=num_boost_round + 50,  # Add more trees
                    max_depth=6,
                    learning_rate=0.05,  # Lower learning rate for fine-tuning
                    random_state=42,
                    eval_metric='logloss',
                )
                
                # Continue training (incremental learning)
                print(f"✓ Loaded base model from {xgb_model_path}")
                print(f"  Base model has {num_boost_round} estimators")
                print(f"  Training {50} additional estimators for incremental learning")
                
                # Use xgb_model parameter for warm start
                model.fit(X_train, y_train, xgb_model=booster)
            except Exception as e:
                print(f"⚠️  Warning: Could not load base model: {e}")
                print("   Training from scratch instead")
                model.fit(X_train, y_train)
    else:
        model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='binary')
    
    print(f"\nTest Set Performance:")
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1 Score:  {f1:.4f}")
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    print(cm)
    
    print("\nClassification Report:")
    unique_pred = np.unique(y_pred)
    if len(unique_pred) < 2:
        print("Warning: Model only predicting one class!")
    print(classification_report(y_test, y_pred, labels=[0, 1], target_names=['Human', 'Bot'], zero_division=0))
    
    return model


def export_to_onnx(model, output_path: str, n_features: int):
    """Export sklearn or XGBoost model to ONNX format."""
    if not HAS_ONNX:
        print("ONNX export not available")
        return
    
    print(f"\nExporting model to ONNX: {output_path}")
    
    # Check if model is XGBoost
    model_type = type(model).__name__
    is_xgboost = 'XGB' in model_type or 'xgboost' in str(type(model))
    
    if is_xgboost:
        # Use onnxmltools for XGBoost models
        print(f"Detected XGBoost model, using onnxmltools converter")
        initial_type = [('float_input', OnnxMLFloatTensorType([None, n_features]))]
        onnx_model = onnxmltools.convert_xgboost(model, initial_types=initial_type)
    else:
        # Use skl2onnx for sklearn models
        print(f"Detected sklearn model ({model_type}), using skl2onnx converter")
        initial_type = [('float_input', FloatTensorType([None, n_features]))]
        onnx_model = convert_sklearn(model, initial_types=initial_type)
    
    with open(output_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
    
    print(f"✓ ONNX model saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Train PacketYeeter ML model")
    parser.add_argument('--input', required=True, help='Input JSONL file with labeled data')
    parser.add_argument('--session-data', help='Optional: Session recordings JSONL for temporal features')
    parser.add_argument('--output', default='model.pkl', help='Output model file (pkl or onnx)')
    parser.add_argument('--model', choices=['rf', 'xgb', 'both'], default='rf',
                        help='Model type: rf (Random Forest), xgb (XGBoost), or both')
    parser.add_argument('--test-size', type=float, default=0.2, help='Test set size (default: 0.2)')
    parser.add_argument('--min-samples', type=int, default=100, help='Minimum samples required')
    parser.add_argument('--base-model', help='Path to existing model for incremental training (warm start)')
    
    args = parser.parse_args()
    
    # Validate base model if provided
    if args.base_model and not os.path.exists(args.base_model):
        print(f"⚠️  Warning: Base model not found: {args.base_model}")
        print("   Will train from scratch instead")
        args.base_model = None
    
    # Load data
    print(f"Loading data from {args.input}...")
    df = load_labeled_data(args.input)
    
    # Optionally load session data
    if args.session_data:
        print(f"Loading session data from {args.session_data}...")
        session_df = load_session_data(args.session_data)
        if not session_df.empty:
            print(f"Merging {len(session_df)} session recordings with {len(df)} labeled detections")
            df = pd.concat([df, session_df], ignore_index=True)
            print(f"Combined dataset: {len(df)} samples")

    
    # Check minimum sample size
    if len(df) < args.min_samples:
        print(f"Error: Not enough samples. Found {len(df)}, need at least {args.min_samples}")
        sys.exit(1)
    
    # Filter to only bot/human labels
    df = df[df['label'].isin(['bot', 'human'])]
    print(f"Using {len(df)} samples with bot/human labels")
    
    # Prepare dataset
    X, y = prepare_dataset(df)
    
    # Check for single-class dataset
    unique_classes = np.unique(y)
    if len(unique_classes) < 2:
        class_name = 'bot' if unique_classes[0] == 1 else 'human'
        print(f"\n" + "="*80)
        print(f"ERROR: Cannot train model - all samples are '{class_name}'")
        print("="*80)
        print(f"\nYou need both 'bot' and 'human' labeled samples to train a classifier.")
        print(f"\nCurrent dataset:")
        print(f"  Total samples: {len(y)}")
        print(f"  {class_name.capitalize()}s: {len(y)}")
        print(f"  {'Bots' if class_name == 'human' else 'Humans'}: 0")
        print(f"\nTo fix this:")
        print(f"  1. Go to the inspector UI (http://your-server:9092)")
        print(f"  2. Mark some detections as 'True Positive' (bot traffic)")
        print(f"  3. Mark some detections as 'False Positive' (legitimate/human traffic)")
        print(f"  4. Ensure you have at least 50 samples of each class")
        print(f"  5. Run this training script again")
        sys.exit(1)
    
    # Check class balance
    bot_ratio = y.sum() / len(y)
    if bot_ratio < 0.1 or bot_ratio > 0.9:
        print(f"\nWarning: Imbalanced dataset (bot ratio: {bot_ratio:.2%})")
        print("Consider collecting more data or using class weights")
        print(f"  Bots: {int(y.sum())} samples")
        print(f"  Humans: {int((1-y).sum())} samples")
        if bot_ratio < 0.2 or bot_ratio > 0.8:
            print(f"\nThis imbalance may affect model performance!")
    
    # Split into train/test
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=args.test_size, random_state=42, stratify=y
        )
    except ValueError as e:
        print(f"\nError splitting dataset: {e}")
        print(f"This usually happens when there aren't enough samples of one class.")
        sys.exit(1)
    
    print(f"\nTrain set: {len(X_train)} samples")
    print(f"Test set:  {len(X_test)} samples")
    
    # Train models
    models = {}
    
    if args.model in ['rf', 'both']:
        rf_model = train_random_forest(X_train, y_train, X_test, y_test)
        models['rf'] = rf_model
    
    if args.model in ['xgb', 'both'] and HAS_XGBOOST:
        # Use existing model as base for incremental learning
        base_model = args.base_model if hasattr(args, 'base_model') else None
        xgb_model = train_xgboost(X_train, y_train, X_test, y_test, base_model_path=base_model)
        if xgb_model:
            models['xgb'] = xgb_model
    
    # Save best model
    if args.model == 'both':
        # Use RF as primary for now
        best_model = models['rf']
        model_name = 'rf'
    else:
        best_model = models[args.model]
        model_name = args.model
    
    # Save model
    if args.output.endswith('.onnx'):
        # For XGBoost, also save native format for future warm starts
        if model_name == 'xgb':
            xgb_json_path = args.output.replace('.onnx', '.json')
            best_model.save_model(xgb_json_path)
            print(f"\n✓ XGBoost native model saved to {xgb_json_path} (for incremental training)")
        
        export_to_onnx(best_model, args.output, X.shape[1])
    else:
        joblib.dump(best_model, args.output)
        print(f"\n✓ Model saved to {args.output}")
        
        # For XGBoost, also save native format if not already .json
        if model_name == 'xgb' and not args.output.endswith('.json'):
            xgb_json_path = args.output.rsplit('.', 1)[0] + '.json'
            best_model.save_model(xgb_json_path)
            print(f"✓ XGBoost native model saved to {xgb_json_path} (for incremental training)")
    
    # Save metadata
    metadata = {
        'model_type': model_name,
        'n_features': X.shape[1],
        'n_samples': len(df),
        'train_size': len(X_train),
        'test_size': len(X_test),
        'timestamp': pd.Timestamp.now().isoformat(),
    }
    
    metadata_path = args.output.replace('.pkl', '_metadata.json').replace('.onnx', '_metadata.json')
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"✓ Metadata saved to {metadata_path}")
    
    print("\n" + "="*80)
    print("Training complete!")
    print("="*80)
    print(f"\nModel: {args.output}")
    print(f"Metadata: {metadata_path}")
    print("\nNext steps:")
    print("  1. Test model with: python test_model.py --model model.pkl")
    print("  2. Deploy to production by updating pkg/ml/model.go")
    print("  3. Monitor false positive rates in production")


if __name__ == '__main__':
    main()
