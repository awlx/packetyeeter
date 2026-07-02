#!/usr/bin/env python3
"""
Train advanced bot detection model using 100+ behavioral features.

This is a replacement for train_model.py that uses the rich feature extraction
from extract_advanced_features.py.

Usage:
    # Extract features first
    python3 scripts/extract_advanced_features.py \
        --sessions /var/cache/packetyeeter/sessions \
        --output /tmp/advanced_features.jsonl
    
    # Train model
    python3 scripts/train_advanced_model.py \
        --input /tmp/advanced_features.jsonl \
        --output /var/lib/packetyeeter/bot_detection_model_v2.json \
        --onnx /var/lib/packetyeeter/bot_detection_model_v2.onnx
"""

import argparse
import json
import sys
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, 
    confusion_matrix, 
    roc_auc_score,
    precision_recall_fscore_support
)


def load_advanced_features(filepath: str) -> tuple:
    """Load advanced features from JSONL."""
    print(f"Loading features from {filepath}...")
    
    data = []
    with open(filepath, 'r') as f:
        for line in f:
            if line.strip():
                try:
                    data.append(json.loads(line))
                except:
                    continue
    
    if not data:
        print("ERROR: No data loaded")
        sys.exit(1)
    
    df = pd.DataFrame(data)
    
    # Separate features from labels and metadata
    exclude_cols = ['label', 'ip', 'session_id']
    feature_cols = [col for col in df.columns if col not in exclude_cols]
    
    X = df[feature_cols]
    y = df['label'].map({'bot': 1, 'human': 0})
    
    # Handle NaN values
    X = X.fillna(0)
    
    # Replace inf values with large numbers
    X = X.replace([np.inf, -np.inf], [1e10, -1e10])
    
    print(f"\n{'='*80}")
    print(f"Dataset loaded successfully")
    print(f"{'='*80}")
    print(f"Total samples: {len(X)}")
    print(f"Feature count: {len(feature_cols)}")
    print(f"\nLabel distribution:")
    for label, count in y.value_counts().items():
        label_name = 'Bot' if label == 1 else 'Human'
        print(f"  {label_name}: {count} ({count/len(y)*100:.1f}%)")
    
    # Check for single-class dataset
    if len(y.unique()) < 2:
        print(f"\n{'='*80}")
        print("ERROR: Need both bot and human samples!")
        print(f"{'='*80}")
        sys.exit(1)
    
    return X, y, feature_cols


def train_xgboost_model(X_train, y_train, X_test, y_test, base_model=None):
    """Train XGBoost classifier with optional warm start."""
    print(f"\n{'='*80}")
    print("Training XGBoost model")
    print(f"{'='*80}")
    
    # XGBoost parameters optimized for bot detection
    params = {
        'objective': 'binary:logistic',
        'eval_metric': ['logloss', 'auc', 'error'],
        'max_depth': 8,
        'learning_rate': 0.1,
        'n_estimators': 200,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'min_child_weight': 3,
        'gamma': 0.1,
        'reg_alpha': 0.01,
        'reg_lambda': 1.0,
        'scale_pos_weight': 1.0,
        'random_state': 42,
    }
    
    # Create model
    if base_model:
        print(f"Loading base model for incremental training: {base_model}")
        try:
            model = xgb.XGBClassifier()
            model.load_model(base_model)
            
            # Update training with new data
            model.fit(
                X_train, y_train,
                eval_set=[(X_train, y_train), (X_test, y_test)],
                verbose=True,
                xgb_model=base_model  # Continue from base model
            )
            print("✓ Incremental training completed")
        except Exception as e:
            print(f"Warning: Failed to load base model: {e}")
            print("Training from scratch instead...")
            model = xgb.XGBClassifier(**params)
            model.fit(
                X_train, y_train,
                eval_set=[(X_train, y_train), (X_test, y_test)],
                verbose=True
            )
    else:
        model = xgb.XGBClassifier(**params)
        model.fit(
            X_train, y_train,
            eval_set=[(X_train, y_train), (X_test, y_test)],
            verbose=True
        )
    
    return model


def evaluate_model(model, X_test, y_test):
    """Evaluate model performance."""
    print(f"\n{'='*80}")
    print("Model Evaluation")
    print(f"{'='*80}")
    
    # Make predictions
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]
    
    # Calculate metrics
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='binary')
    auc = roc_auc_score(y_test, y_pred_proba)
    
    print(f"\nOverall Metrics:")
    print(f"  Accuracy:  {(y_pred == y_test).mean():.3f}")
    print(f"  Precision: {precision:.3f}")
    print(f"  Recall:    {recall:.3f}")
    print(f"  F1 Score:  {f1:.3f}")
    print(f"  AUC-ROC:   {auc:.3f}")
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    print(f"\nConfusion Matrix:")
    print(f"                 Predicted")
    print(f"               Human    Bot")
    print(f"  Actual Human    {tn:4d}  {fp:4d}")
    print(f"         Bot      {fn:4d}  {tp:4d}")
    
    # False positive rate (critical for production)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    
    print(f"\nError Rates:")
    print(f"  False Positive Rate: {fpr:.3f} ({fp}/{fp+tn})")
    print(f"  False Negative Rate: {fnr:.3f} ({fn}/{fn+tp})")
    
    # Classification report
    print(f"\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Human', 'Bot']))
    
    return {
        'accuracy': (y_pred == y_test).mean(),
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'auc': auc,
        'fpr': fpr,
        'fnr': fnr,
        'confusion_matrix': cm
    }


def print_feature_importance(model, feature_names, top_n=20):
    """Print top feature importances."""
    print(f"\n{'='*80}")
    print(f"Top {top_n} Most Important Features")
    print(f"{'='*80}")
    
    importance = model.feature_importances_
    indices = np.argsort(importance)[::-1][:top_n]
    
    for i, idx in enumerate(indices, 1):
        print(f"{i:2d}. {feature_names[idx]:40s} {importance[idx]:.4f}")


def export_to_onnx(model, feature_names, output_path):
    """Export model to ONNX format."""
    try:
        import onnx
        import onnxruntime as ort
        
        print(f"\n{'='*80}")
        print("Exporting to ONNX")
        print(f"{'='*80}")
        
        # Save to ONNX
        initial_type = [('float_input', onnx.TensorProto.FLOAT, [None, len(feature_names)])]
        model.save_model('/tmp/temp_model.json')
        
        # Use XGBoost's built-in ONNX export
        import xgboost as xgb
        booster = model.get_booster()
        
        # Create ONNX model
        from onnxmltools.convert import convert_xgboost
        from onnxmltools.convert.common.data_types import FloatTensorType
        
        initial_types = [('float_input', FloatTensorType([None, len(feature_names)]))]
        onnx_model = convert_xgboost(booster, initial_types=initial_types)
        
        # Save ONNX model
        with open(output_path, 'wb') as f:
            f.write(onnx_model.SerializeToString())
        
        print(f"✓ ONNX model saved to: {output_path}")
        
        # Verify ONNX model loads
        session = ort.InferenceSession(output_path)
        print(f"✓ ONNX model verified successfully")
        print(f"  Input shape: {session.get_inputs()[0].shape}")
        print(f"  Output shape: {session.get_outputs()[0].shape}")
        
    except ImportError as e:
        print(f"\n⚠️  Warning: Cannot export to ONNX: {e}")
        print("Install with: pip install onnx onnxruntime onnxmltools")
    except Exception as e:
        print(f"\n⚠️  Warning: ONNX export failed: {e}")


def main():
    parser = argparse.ArgumentParser(description="Train advanced bot detection model")
    parser.add_argument('--input', required=True, 
                        help='Input advanced features JSONL')
    parser.add_argument('--output', required=True, 
                        help='Output XGBoost model file (.json)')
    parser.add_argument('--onnx', required=True, 
                        help='Output ONNX model file (.onnx)')
    parser.add_argument('--base-model', 
                        help='Base model for incremental training')
    parser.add_argument('--test-size', type=float, default=0.2,
                        help='Test set size (default: 0.2)')
    
    args = parser.parse_args()
    
    # Load data
    X, y, feature_names = load_advanced_features(args.input)
    
    # Split train/test
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=args.test_size, 
            random_state=42, 
            stratify=y
        )
    except ValueError as e:
        print(f"Error splitting data: {e}")
        print("Trying without stratification...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=args.test_size, 
            random_state=42
        )
    
    print(f"\nTrain set: {len(X_train)} samples")
    print(f"Test set:  {len(X_test)} samples")
    
    # Train model
    model = train_xgboost_model(X_train, y_train, X_test, y_test, args.base_model)
    
    # Evaluate
    metrics = evaluate_model(model, X_test, y_test)
    
    # Feature importance
    print_feature_importance(model, feature_names)
    
    # Save model
    print(f"\n{'='*80}")
    print("Saving model")
    print(f"{'='*80}")
    model.save_model(args.output)
    print(f"✓ XGBoost model saved to: {args.output}")
    
    # Export to ONNX
    export_to_onnx(model, feature_names, args.onnx)
    
    print(f"\n{'='*80}")
    print("Training complete!")
    print(f"{'='*80}")
    print(f"\nNext steps:")
    print(f"  1. Review the metrics above")
    print(f"  2. Test on sessions: python3 scripts/test_on_sessions.py")
    print(f"  3. Deploy: cp {args.output} /var/lib/packetyeeter/")
    print(f"  4. Restart analyzer: systemctl restart packetyeeter-analyzer")


if __name__ == '__main__':
    main()
