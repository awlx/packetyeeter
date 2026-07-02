#!/tmp/venv/bin/python3
"""
Convert session recordings to training dataset

This script processes saved session recordings and converts them
into labeled training examples for ML model training.

Session recordings are automatically saved to:
  /var/lib/packetyeeter/sessions/recording-{ip}-{timestamp}.jsonl

Usage:
    # Convert all sessions from last 7 days
    python3 scripts/sessions_to_training.py --days 7

    # Convert specific date range
    python3 scripts/sessions_to_training.py --start 2026-01-20 --end 2026-01-29

    # Output to specific file
    python3 scripts/sessions_to_training.py --output /path/to/training.jsonl
"""

import argparse
import json
import glob
import os
import re
from datetime import datetime, timedelta
from pathlib import Path


def load_sessions(sessions_dir, start_date=None, end_date=None):
    """Load session recordings from disk."""
    sessions_dir = Path(sessions_dir)
    
    if not sessions_dir.exists():
        print(f"❌ Sessions directory not found: {sessions_dir}")
        return []
    
    # Find all session files (new format: recording-{ip}-{timestamp}.jsonl)
    pattern = str(sessions_dir / "recording-*.jsonl")
    files = glob.glob(pattern)
    
    if not files:
        print(f"⚠️  No recording files found in {sessions_dir}")
        return []
    
    print(f"Found {len(files)} recording files")
    
    sessions = []
    for filepath in sorted(files):
        # Parse timestamp from filename (recording-{ip}-YYYY-MM-DDTHH-MM-SS.jsonl)
        # Use regex to extract timestamp from end of filename (handles IPv6 with many hyphens)
        filename = os.path.basename(filepath)
        try:
            # Match timestamp pattern at end: YYYY-MM-DDTHH-MM-SS.jsonl
            match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2})\.jsonl$', filename)
            if not match:
                print(f"⚠️  Skipping file with unexpected name: {filename}")
                continue
            
            timestamp_str = match.group(1)
            file_datetime = datetime.strptime(timestamp_str, "%Y-%m-%dT%H-%M-%S")
            file_date = file_datetime.date()
        except (ValueError, IndexError) as e:
            print(f"⚠️  Skipping file with unexpected name: {filename} ({e})")
            continue
        
        # Filter by date range
        if start_date and file_date < start_date:
            continue
        if end_date and file_date > end_date:
            continue
        
        # Load session from file (each file contains one session as one JSONL line)
        with open(filepath, 'r') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    session = json.loads(line.strip())
                    sessions.append(session)
                except json.JSONDecodeError as e:
                    print(f"⚠️  Error parsing {filename}:{line_num}: {e}")
    
    print(f"✅ Loaded {len(sessions)} session recordings")
    return sessions


def session_to_training_example(session):
    """Convert a session recording to a training example."""
    detection = session.get('Detection', {})
    outcome = session.get('Outcome', 'unknown')
    
    # Use explicit Label field from recording (tp/fp/tn/fn/bot/human/manual)
    # This is set by the user via the Inspector UI or feedback endpoints
    session_label = session.get('Label', '')
    
    # Map label to binary classification
    # tp (true positive), fn (false negative), bot = malicious
    # fp (false positive), tn (true negative), human = legitimate
    # manual/unknown = use outcome-based heuristic as fallback
    if session_label in ['tp', 'fn', 'bot']:
        label = 'bot'
    elif session_label in ['fp', 'tn', 'human']:
        label = 'human'
    else:
        # Fallback to outcome-based label if no explicit label
        # - "blocked" / "escalated" = malicious bot
        # - "disappeared" = likely bot (stopped when detected)
        # - "allowed" = human or legitimate bot
        if outcome in ['blocked', 'escalated']:
            label = 'bot'
        elif outcome == 'disappeared':
            label = 'bot'  # Suspicious behavior
        elif outcome == 'allowed':
            label = 'human'
        else:
            return None  # Skip unknown outcomes without labels
    
    # Extract features from detection
    training_example = {
        'label': label,
        'signal_count': detection.get('signal_count', 0),
        'confidence': detection.get('confidence', 0.0),
        'ml_confidence': detection.get('ml_confidence', 0.0),
        'signal_breakdown': detection.get('signal_breakdown', {}),
        'source_breakdown': detection.get('source_breakdown', {}),
        
        # Session metadata
        'session_duration': session.get('Duration', 0) / 1e9,  # nanoseconds to seconds
        'pre_event_count': len(session.get('PreEvents', [])),
        'post_event_count': len(session.get('PostEvents', [])),
        'total_events': session.get('TotalEvents', 0),
        'outcome': outcome,
        'original_label': session_label,  # Preserve the original label (tp/fp/tn/fn/bot/human/manual)
        
        # Calculated features
        'time_span': detection.get('time_span', 0),
        'threat_score': detection.get('threat_score', 0.0),
        'is_known_scanner': detection.get('is_known_scanner', False),
        'is_cloud': detection.get('is_cloud', False),
        'is_tor': detection.get('is_tor', False),
        'is_vpn': detection.get('is_vpn', False),
        'open_ports': detection.get('open_ports', 0),
        'reputation_score': detection.get('reputation_score', 0.0),
        'detection_history': detection.get('detection_history', 0),
        'request_rate': detection.get('request_rate', 0.0),
        'time_of_day': detection.get('time_of_day', 0),
        'day_of_week': detection.get('day_of_week', 0),
        'is_bursty': detection.get('is_bursty', False),
        
        # Metadata for reference
        'ip': session.get('IP', ''),
        'session_id': session.get('SessionID', ''),
        'start_time': session.get('StartTime', ''),
    }
    
    return training_example


def main():
    parser = argparse.ArgumentParser(description="Convert session recordings to training data")
    parser.add_argument('--sessions-dir', default='/var/cache/packetyeeter/sessions',
                        help='Directory containing session recordings')
    parser.add_argument('--output', default='/var/cache/packetyeeter/sessions_training.jsonl',
                        help='Output training dataset file')
    parser.add_argument('--days', type=int, help='Process sessions from last N days')
    parser.add_argument('--start', help='Start date (YYYY-MM-DD)')
    parser.add_argument('--end', help='End date (YYYY-MM-DD)')
    parser.add_argument('--append', action='store_true',
                        help='Append to existing output file instead of overwriting')
    
    args = parser.parse_args()
    
    # Parse date range
    start_date = None
    end_date = None
    
    if args.days:
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=args.days)
        print(f"Processing sessions from {start_date} to {end_date}")
    elif args.start or args.end:
        if args.start:
            start_date = datetime.strptime(args.start, '%Y-%m-%d').date()
        if args.end:
            end_date = datetime.strptime(args.end, '%Y-%m-%d').date()
        print(f"Processing sessions: {start_date or 'beginning'} to {end_date or 'now'}")
    
    # Load sessions
    sessions = load_sessions(args.sessions_dir, start_date, end_date)
    
    if not sessions:
        print("No sessions to process")
        return
    
    # Convert to training examples
    print("\nConverting sessions to training examples...")
    training_examples = []
    skipped = 0
    
    for session in sessions:
        example = session_to_training_example(session)
        if example:
            training_examples.append(example)
        else:
            skipped += 1
    
    print(f"✅ Converted {len(training_examples)} sessions to training examples")
    if skipped > 0:
        print(f"⚠️  Skipped {skipped} sessions (unknown outcome)")
    
    # Label distribution
    labels = {}
    for example in training_examples:
        label = example['label']
        labels[label] = labels.get(label, 0) + 1
    
    print("\n📊 Label Distribution:")
    for label, count in sorted(labels.items()):
        pct = count / len(training_examples) * 100
        print(f"  {label:15s}: {count:5d} ({pct:5.1f}%)")
    
    # Write output
    print(f"\nWriting to {args.output}...")
    
    # Create output directory if needed
    os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
    
    # Open in append or write mode
    mode = 'a' if args.append else 'w'
    with open(args.output, mode) as f:
        for example in training_examples:
            f.write(json.dumps(example) + '\n')
    
    print(f"✅ Wrote {len(training_examples)} training examples")
    
    if args.append:
        # Count total lines in file
        with open(args.output, 'r') as f:
            total = sum(1 for _ in f)
        print(f"   Total examples in file: {total}")
    
    print("\nNext steps:")
    print(f"  1. Merge with manual labels: cat labeled_dataset.jsonl {args.output} > combined.jsonl")
    print(f"  2. Train model: python3 scripts/train_model.py --input combined.jsonl --output model.onnx")
    print(f"  3. Or use --base-model for incremental training")


if __name__ == '__main__':
    main()
