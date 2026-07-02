#!/usr/bin/env python3
"""
Show feature extraction results for debugging.

This script extracts features from a few sessions and displays them
to verify that the advanced features are capturing meaningful variance.

Usage:
    python3 scripts/show_features.py \
        --sessions /var/cache/packetyeeter/sessions \
        --limit 5
"""

import argparse
import json
import glob
from pathlib import Path
import sys

# Import the feature extraction functions
sys.path.insert(0, str(Path(__file__).parent))
from extract_advanced_features import extract_advanced_features_from_session


def main():
    parser = argparse.ArgumentParser(description="Show feature extraction")
    parser.add_argument('--sessions', default='/var/cache/packetyeeter/sessions',
                        help='Sessions directory')
    parser.add_argument('--limit', type=int, default=5,
                        help='Number of sessions to show')
    
    args = parser.parse_args()
    
    # Load sessions
    sessions_dir = Path(args.sessions)
    pattern = str(sessions_dir / "recording-*.jsonl")
    files = glob.glob(pattern)
    
    if not files:
        print(f"No session files found in {args.sessions}")
        return
    
    print(f"Found {len(files)} session files")
    print(f"Showing first {args.limit} labeled sessions:\n")
    
    shown = 0
    for filepath in sorted(files):
        if shown >= args.limit:
            break
        
        with open(filepath, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        session = json.loads(line)
                        label = session.get('Label', '')
                        
                        if not label or label not in ['tp', 'fp', 'tn', 'fn', 'bot', 'human']:
                            continue
                        
                        features = extract_advanced_features_from_session(session)
                        
                        print("=" * 80)
                        print(f"Session: {features['session_id']}")
                        print(f"IP: {features['ip']}")
                        print(f"Label: {features['label']}")
                        print("-" * 80)
                        
                        # Group features by category
                        categories = {
                            'temporal': [],
                            'path': [],
                            'header': [],
                            'ja4': [],
                            'signal': [],
                            'behavior': [],
                            'original': []
                        }
                        
                        for key, value in sorted(features.items()):
                            if key in ['label', 'ip', 'session_id']:
                                continue
                            
                            for cat in categories.keys():
                                if key.startswith(cat + '_'):
                                    categories[cat].append((key, value))
                                    break
                            else:
                                categories['original'].append((key, value))
                        
                        # Print by category
                        for cat_name, cat_features in categories.items():
                            if cat_features:
                                print(f"\n{cat_name.upper()} FEATURES:")
                                for key, value in cat_features:
                                    # Format numbers nicely
                                    if isinstance(value, float):
                                        print(f"  {key:40s} {value:10.4f}")
                                    else:
                                        print(f"  {key:40s} {value:10}")
                        
                        print("\n")
                        shown += 1
                        
                        if shown >= args.limit:
                            break
                        
                    except Exception as e:
                        print(f"Warning: Failed to process session: {e}")
                        continue
    
    if shown == 0:
        print("No labeled sessions found!")
        print("\nTo create labeled sessions:")
        print("  1. Go to Inspector UI: http://your-server:9092")
        print("  2. Navigate to 'Labeling' tab")
        print("  3. Mark detections as TP (bot) or FP (human)")
        print("  4. Click 'Start Recording' for labeled IPs")
        print("  5. Wait 5 minutes for recordings to complete")


if __name__ == '__main__':
    main()
