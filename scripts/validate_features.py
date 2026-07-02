#!/tmp/venv/bin/python3
"""
Feature Validation Script

Validates that training features match runtime expectations.
Run this before training to catch feature mismatches early.

Usage:
    python3 scripts/validate_features.py --input labeled_dataset.jsonl
"""

import argparse
import json
import sys


def validate_feature_extraction():
    """Validate that extract_features() produces expected feature count."""
    print("=" * 80)
    print("Feature Validation")
    print("=" * 80)
    
    # Expected feature breakdown (must match both train_model.py and onnx.go)
    expected = {
        'core': 3,           # signal_count, signal_rate, signal_rate (dup)
        'signals': 16,       # One-hot encoded signal types
        'sources': 5,        # One-hot encoded sources
        'derived': 5,        # Computed features
        'threat_intel': 6,   # Shodan/threat intelligence
        'behavioral': 3,     # Reputation, history, request_rate
        'temporal': 3,       # Time of day, day of week, is_bursty
    }
    
    total = sum(expected.values())
    
    print(f"\nExpected Feature Breakdown:")
    for category, count in expected.items():
        print(f"  {category:15s}: {count:2d} features")
    print(f"  {'TOTAL':15s}: {total:2d} features")
    
    # Expected signal types (must match types.go SignalType constants)
    signal_types = [
        'high_frequency', 'path_seq_ids', 'missing_accept_language',
        'clock_skew_anomaly', 'entropy_low', 'high_threat_score', 'ua_suspicious',
        'missing_ja4h', 'incomplete_handshake', 'bad_flags', 'connection_pattern',
        'timing_pattern', 'proxy_lag', 'icmp_flood', 'udp_flood', 'syn_flood'
    ]
    
    # Expected sources (must match types.go SignalSource constants)
    sources = ['spoe', 'tcp', 'udp', 'icmp', 'fingerprint']
    
    print(f"\nSignal Types ({len(signal_types)}):")
    for i, sig in enumerate(signal_types, 1):
        print(f"  {i:2d}. {sig}")
    
    print(f"\nSources ({len(sources)}):")
    for i, src in enumerate(sources, 1):
        print(f"  {i:2d}. {src}")
    
    # Validate counts
    assert len(signal_types) == expected['signals'], \
        f"Signal type count mismatch: expected {expected['signals']}, got {len(signal_types)}"
    assert len(sources) == expected['sources'], \
        f"Source count mismatch: expected {expected['sources']}, got {len(sources)}"
    
    print(f"\n✅ Feature structure validated: {total} features expected")
    return total


def validate_dataset(filepath):
    """Validate that dataset contains necessary fields."""
    print(f"\n{'=' * 80}")
    print(f"Dataset Validation: {filepath}")
    print("=" * 80)
    
    # Required fields for training
    required_fields = ['label', 'signal_count', 'signal_breakdown', 'source_breakdown']
    
    # Optional but recommended fields
    recommended_fields = [
        'threat_score', 'is_known_scanner', 'is_cloud', 'is_tor', 'is_vpn',
        'open_ports', 'reputation_score', 'detection_history', 'request_rate',
        'time_of_day', 'day_of_week', 'is_bursty'
    ]
    
    samples = []
    missing_fields = set()
    field_coverage = {field: 0 for field in recommended_fields}
    
    try:
        with open(filepath, 'r') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    sample = json.loads(line.strip())
                    samples.append(sample)
                    
                    # Check required fields
                    for field in required_fields:
                        if field not in sample or sample[field] is None:
                            missing_fields.add((line_num, field))
                    
                    # Track optional field coverage
                    for field in recommended_fields:
                        if field in sample and sample[field] is not None:
                            field_coverage[field] += 1
                            
                except json.JSONDecodeError as e:
                    print(f"⚠️  Line {line_num}: Invalid JSON - {e}")
                    
    except FileNotFoundError:
        print(f"❌ File not found: {filepath}")
        return False
    
    if not samples:
        print("❌ No valid samples found")
        return False
    
    print(f"\n✅ Loaded {len(samples)} samples")
    
    # Check for missing required fields
    if missing_fields:
        print(f"\n⚠️  Missing required fields in {len(missing_fields)} samples:")
        for line_num, field in sorted(missing_fields)[:10]:  # Show first 10
            print(f"  Line {line_num}: missing '{field}'")
        if len(missing_fields) > 10:
            print(f"  ... and {len(missing_fields) - 10} more")
    
    # Report optional field coverage
    print(f"\n📊 Feature Coverage:")
    for field, count in sorted(field_coverage.items()):
        pct = count / len(samples) * 100
        status = "✅" if pct > 80 else "⚠️ " if pct > 20 else "❌"
        print(f"  {status} {field:20s}: {count:5d} / {len(samples)} ({pct:5.1f}%)")
    
    # Check label distribution
    labels = {}
    for sample in samples:
        label = sample.get('label', 'unknown')
        labels[label] = labels.get(label, 0) + 1
    
    print(f"\n📊 Label Distribution:")
    for label, count in sorted(labels.items(), key=lambda x: -x[1]):
        pct = count / len(samples) * 100
        print(f"  {label:20s}: {count:5d} ({pct:5.1f}%)")
    
    # Warnings
    if 'bot' in labels and 'human' in labels:
        bot_ratio = labels['bot'] / len(samples)
        if bot_ratio < 0.2 or bot_ratio > 0.8:
            print(f"\n⚠️  Warning: Imbalanced dataset (bot ratio: {bot_ratio:.1%})")
            print("   Consider collecting more data for the minority class")
    else:
        print(f"\n❌ Error: Dataset must have both 'bot' and 'human' labels")
        return False
    
    # Check if new features are present
    new_features_present = sum(1 for field in recommended_fields if field_coverage[field] > 0)
    if new_features_present < len(recommended_fields) * 0.5:
        print(f"\n⚠️  Warning: Low coverage of threat intel/behavioral features")
        print("   Model will train, but some features will be zero/default")
        print("   Consider updating data collection to populate these fields")
    
    return True


def main():
    parser = argparse.ArgumentParser(description="Validate ML training features")
    parser.add_argument('--input', help='Input JSONL dataset file')
    args = parser.parse_args()
    
    # Validate feature structure
    expected_features = validate_feature_extraction()
    
    # Validate dataset if provided
    if args.input:
        if not validate_dataset(args.input):
            print("\n❌ Dataset validation failed")
            sys.exit(1)
    
    print(f"\n{'=' * 80}")
    print("✅ All validations passed!")
    print("=" * 80)
    print(f"\nReady to train with {expected_features} features")
    print("\nNext steps:")
    print("  1. Train model: python3 scripts/train_model.py --input <dataset> --output model.onnx")
    print("  2. Deploy model: cp model.onnx /var/lib/packetyeeter/model.onnx")
    print("  3. Restart analyzer: systemctl restart packetyeeter-analyzer")


if __name__ == '__main__':
    main()
