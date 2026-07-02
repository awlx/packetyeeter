#!/usr/bin/env python3
"""
Advanced Feature Extraction - Simplified for Go compatibility

Extracts features that can be computed in real-time from event streams.
This matches what we'll implement in pkg/ml/onnx.go

Total: ~126 features that are practical for live detection
- Temporal: 25 features (request timing, bursts)
- Path: 20 features (diversity, enumeration patterns)
- Header: 25 features (consistency, User-Agent analysis)
- Signal: 25 features (HTTP 404/403 tracking + status code analysis)
- Fingerprint: 10 features (JA4/JA4H/JA4T diversity and consistency)
- Behavioral: 10 features (pre/post detection changes)
- Original: 5 features (baseline detection metrics)
- Metadata: label, ip, session_id (not used for training)
"""

import argparse
import json
import re
import glob
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List
import numpy as np
from datetime import datetime, timedelta

# Note: scipy is optional - we'll compute simplified versions if not available
try:
    from scipy import stats as scipy_stats
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False
    print("Warning: scipy not available, using simplified statistics")


def extract_temporal_features(events: List[Dict]) -> Dict:
    """Extract timing patterns (25 features)."""
    if not events or len(events) < 2:
        return {f'temporal_{k}': 0 for k in [
            'event_count', 'duration_sec', 'requests_per_sec', 'requests_per_min',
            'avg_gap', 'std_gap', 'min_gap', 'max_gap', 'median_gap',
            'burst_coef', 'gaps_under_10ms', 'gaps_under_100ms', 'gaps_over_1s', 'gaps_over_5s',
            'peak_rate_1s', 'peak_rate_5s', 'first_min_count', 'last_min_count', 'rate_accel',
            'timing_regularity', 'gap_p25', 'gap_p75', 'gap_p90', 'gap_p95', 'gap_p99'
        ]}
    
    # Parse timestamps
    timestamps = []
    for event in events:
        ts_str = event.get('Timestamp', event.get('timestamp', ''))
        if ts_str:
            try:
                timestamps.append(datetime.fromisoformat(ts_str.replace('Z', '+00:00')))
            except:
                pass
    
    if len(timestamps) < 2:
        return {f'temporal_{k}': 0 for k in [
            'event_count', 'duration_sec', 'requests_per_sec', 'requests_per_min',
            'avg_gap', 'std_gap', 'min_gap', 'max_gap', 'median_gap',
            'burst_coef', 'gaps_under_10ms', 'gaps_under_100ms', 'gaps_over_1s', 'gaps_over_5s',
            'peak_rate_1s', 'peak_rate_5s', 'first_min_count', 'last_min_count', 'rate_accel',
            'timing_regularity', 'gap_p25', 'gap_p75', 'gap_p90', 'gap_p95', 'gap_p99'
        ]}
    
    timestamps.sort()
    duration = (timestamps[-1] - timestamps[0]).total_seconds()
    
    # Inter-request gaps
    gaps = [(timestamps[i+1] - timestamps[i]).total_seconds() for i in range(len(timestamps)-1)]
    gaps_array = np.array(gaps)
    
    # Basic stats
    avg_gap = float(np.mean(gaps_array))
    std_gap = float(np.std(gaps_array))
    min_gap = float(np.min(gaps_array))
    max_gap = float(np.max(gaps_array))
    median_gap = float(np.median(gaps_array))
    
    # Percentiles
    p25 = float(np.percentile(gaps_array, 25))
    p75 = float(np.percentile(gaps_array, 75))
    p90 = float(np.percentile(gaps_array, 90))
    p95 = float(np.percentile(gaps_array, 95))
    p99 = float(np.percentile(gaps_array, 99))
    
    # Burst coefficient
    burst_coef = std_gap / avg_gap if avg_gap > 0 else 0
    
    # Rates
    rps = len(events) / duration if duration > 0 else 0
    rpm = rps * 60
    
    # Gap counts
    gaps_under_10ms = sum(1 for g in gaps if g < 0.01)
    gaps_under_100ms = sum(1 for g in gaps if g < 0.1)
    gaps_over_1s = sum(1 for g in gaps if g > 1.0)
    gaps_over_5s = sum(1 for g in gaps if g > 5.0)
    
    # Peak rates
    peak_1s = max(sum(1 for t in timestamps[i:] if (t - timestamps[i]).total_seconds() <= 1.0) for i in range(len(timestamps)))
    peak_5s = max(sum(1 for t in timestamps[i:] if (t - timestamps[i]).total_seconds() <= 5.0) for i in range(len(timestamps)))
    
    # First/last minute
    first_min_end = timestamps[0] + timedelta(seconds=60)
    last_min_start = timestamps[-1] - timedelta(seconds=60)
    first_min_count = sum(1 for ts in timestamps if ts <= first_min_end)
    last_min_count = sum(1 for ts in timestamps if ts >= last_min_start)
    rate_accel = (last_min_count - first_min_count) / first_min_count if first_min_count > 0 else 0
    
    # Timing regularity (low burst_coef = too regular = bot)
    timing_regularity = 1.0 if burst_coef < 0.1 and avg_gap > 0 else 0.0
    
    return {
        'temporal_event_count': len(events),
        'temporal_duration_sec': duration,
        'temporal_requests_per_sec': rps,
        'temporal_requests_per_min': rpm,
        'temporal_avg_gap': avg_gap,
        'temporal_std_gap': std_gap,
        'temporal_min_gap': min_gap,
        'temporal_max_gap': max_gap,
        'temporal_median_gap': median_gap,
        'temporal_burst_coef': burst_coef,
        'temporal_gaps_under_10ms': gaps_under_10ms,
        'temporal_gaps_under_100ms': gaps_under_100ms,
        'temporal_gaps_over_1s': gaps_over_1s,
        'temporal_gaps_over_5s': gaps_over_5s,
        'temporal_peak_rate_1s': peak_1s,
        'temporal_peak_rate_5s': peak_5s,
        'temporal_first_min_count': first_min_count,
        'temporal_last_min_count': last_min_count,
        'temporal_rate_accel': rate_accel,
        'temporal_timing_regularity': timing_regularity,
        'temporal_gap_p25': p25,
        'temporal_gap_p75': p75,
        'temporal_gap_p90': p90,
        'temporal_gap_p95': p95,
        'temporal_gap_p99': p99,
    }


def extract_path_features(events: List[Dict]) -> Dict:
    """Extract path patterns (20 features)."""
    paths = []
    methods = []
    
    for event in events:
        metadata = event.get('Metadata', event.get('metadata', {}))
        if isinstance(metadata, dict):
            path = metadata.get('path', '')
            method = metadata.get('method', '')
            if path:
                paths.append(path)
            if method:
                methods.append(method)
    
    if not paths:
        return {f'path_{k}': 0 for k in [
            'unique_count', 'diversity', 'has_numeric_enum', 'has_alpha_enum',
            'sequential_numeric', 'avg_depth', 'std_depth', 'entropy',
            'method_diversity', 'get_ratio', 'post_ratio', 'has_query_strings',
            'query_diversity', 'accessing_static', 'accessing_api', 'repeat_ratio',
            'most_common_ratio', 'unique_methods', 'path_length_avg', 'path_length_std'
        ]}
    
    unique_paths = len(set(paths))
    path_diversity = unique_paths / len(paths)
    
    # Enumeration detection
    numeric_enum = int(any(re.search(r'/\d+/?', p) for p in paths))
    alpha_enum = int(any(re.search(r'/[a-z]/[a-z]', p) for p in paths))
    
    # Sequential numbers
    numbers = []
    for p in paths:
        matches = re.findall(r'/(\d+)(?:/|$|\?)', p)
        for m in matches:
            try:
                numbers.append(int(m))
            except:
                pass
    sequential = 0
    if len(numbers) >= 3:
        numbers.sort()
        diffs = [numbers[i+1] - numbers[i] for i in range(len(numbers)-1)]
        if diffs and np.std(diffs) < 2:
            sequential = 1
    
    # Path depth
    depths = [len(p.split('/')) for p in paths]
    avg_depth = float(np.mean(depths))
    std_depth = float(np.std(depths)) if len(depths) > 1 else 0
    
    # Entropy
    all_chars = ''.join(paths)
    char_counts = Counter(all_chars)
    total = len(all_chars)
    entropy = -sum((c/total) * np.log2(c/total) for c in char_counts.values() if c > 0) if total > 0 else 0
    
    # Methods
    method_counts = Counter(methods)
    method_diversity = len(set(methods)) / len(methods) if methods else 0
    get_ratio = method_counts.get('GET', 0) / len(methods) if methods else 0
    post_ratio = method_counts.get('POST', 0) / len(methods) if methods else 0
    
    # Query strings
    has_qs = int(any('?' in p for p in paths))
    query_strings = [p.split('?', 1)[1] for p in paths if '?' in p]
    qs_diversity = len(set(query_strings)) / len(query_strings) if query_strings else 0
    
    # Static files
    static_exts = {'jpg', 'jpeg', 'png', 'gif', 'css', 'js', 'ico', 'svg', 'woff', 'ttf'}
    accessing_static = int(any(p.split('.')[-1].lower() in static_exts for p in paths if '.' in p))
    
    # API endpoints
    accessing_api = int(any(kw in p for p in paths for kw in ['/api/', '/v1/', '/v2/', '/rest/', '/graphql']))
    
    # Path repetition
    path_counts = Counter(paths)
    most_common = path_counts.most_common(1)[0][1] if path_counts else 0
    repeat_ratio = most_common / len(paths)
    most_common_ratio = most_common / len(paths)
    
    # Path lengths
    lengths = [len(p) for p in paths]
    path_length_avg = float(np.mean(lengths))
    path_length_std = float(np.std(lengths)) if len(lengths) > 1 else 0
    
    return {
        'path_unique_count': unique_paths,
        'path_diversity': path_diversity,
        'path_has_numeric_enum': numeric_enum,
        'path_has_alpha_enum': alpha_enum,
        'path_sequential_numeric': sequential,
        'path_avg_depth': avg_depth,
        'path_std_depth': std_depth,
        'path_entropy': entropy,
        'path_method_diversity': method_diversity,
        'path_get_ratio': get_ratio,
        'path_post_ratio': post_ratio,
        'path_has_query_strings': has_qs,
        'path_query_diversity': qs_diversity,
        'path_accessing_static': accessing_static,
        'path_accessing_api': accessing_api,
        'path_repeat_ratio': repeat_ratio,
        'path_most_common_ratio': most_common_ratio,
        'path_unique_methods': len(set(methods)),
        'path_length_avg': path_length_avg,
        'path_length_std': path_length_std,
    }


def extract_header_features(events: List[Dict]) -> Dict:
    """Extract header patterns (25 features)."""
    user_agents = []
    accept_langs = []
    referers = []
    
    for event in events:
        metadata = event.get('Metadata', event.get('metadata', {}))
        if isinstance(metadata, dict):
            ua = metadata.get('user_agent', '')
            accept = metadata.get('accept_language', '')
            referer = metadata.get('referer', '')
            if ua:
                user_agents.append(ua)
            if accept:
                accept_langs.append(accept)
            if referer:
                referers.append(referer)
    
    # UA analysis
    ua = user_agents[0] if user_agents else ''
    bot_keywords = ['bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python', 
                    'java', 'go-http', 'axios', 'requests', 'selenium', 'phantom',
                    'headless', 'puppeteer', 'node-fetch']
    browser_keywords = ['Chrome', 'Firefox', 'Safari', 'Edge', 'Opera']
    
    has_bot_kw = int(any(kw in ua.lower() for kw in bot_keywords))
    has_browser_kw = int(any(kw in ua for kw in browser_keywords))
    has_version = int(bool(re.search(r'\d+\.\d+', ua)))
    has_platform = int(any(p in ua for p in ['Windows', 'Mac', 'Linux', 'Android', 'iOS']))
    has_mozilla = int('Mozilla/' in ua)
    
    return {
        'header_ua_consistent': int(len(set(user_agents)) == 1) if user_agents else 1,
        'header_lang_consistent': int(len(set(accept_langs)) == 1) if accept_langs else 1,
        'header_referer_consistent': int(len(set(referers)) == 1) if referers else 1,
        'header_missing_accept_lang': int(not accept_langs),
        'header_has_bot_keyword': has_bot_kw,
        'header_has_browser_keyword': has_browser_kw,
        'header_ua_has_version': has_version,
        'header_ua_has_platform': has_platform,
        'header_ua_has_mozilla': has_mozilla,
        'header_ua_length': len(ua),
        'header_ua_word_count': len(ua.split()),
        'header_ua_paren_count': ua.count('('),
        'header_unique_uas': len(set(user_agents)),
        'header_unique_langs': len(set(accept_langs)),
        'header_has_referer': int(len(referers) > 0),
        'header_referer_diversity': len(set(referers)) / len(referers) if referers else 0,
        'header_ua_changes': len(set(user_agents)) - 1 if len(user_agents) > 0 else 0,
        'header_lang_changes': len(set(accept_langs)) - 1 if len(accept_langs) > 0 else 0,
        'header_ua_avg_length': float(np.mean([len(ua) for ua in user_agents])) if user_agents else 0,
        'header_ua_std_length': float(np.std([len(ua) for ua in user_agents])) if len(user_agents) > 1 else 0,
        'header_referer_count': len(referers),
        'header_lang_count': len(accept_langs),
        'header_ua_count': len(user_agents),
        'header_missing_referer': int(len(referers) == 0),
        'header_ua_complexity': len(ua.split()) * ua.count('(') if ua else 0,
    }


def extract_signal_features(events: List[Dict]) -> Dict:
    """Extract signal patterns (25 features - includes HTTP error tracking + status analysis)."""
    signal_types = []
    
    for event in events:
        sig_type = event.get('Type', event.get('type', ''))
        if sig_type:
            signal_types.append(sig_type)
    
    if not signal_types:
        return {f'signal_{k}': 0 for k in [
            'diversity', 'entropy', 'most_common_ratio', 'unique_count',
            'high_freq_count', 'path_enum_count', 'missing_header_count',
            'clock_skew_count', 'entropy_low_count', 'threat_score_count',
            'ua_suspicious_count', 'fingerprint_count', 'connection_count',
            'timing_count', 'flood_count'
        ]}
    
    signal_counts = Counter(signal_types)
    total = len(signal_types)
    
    diversity = len(signal_counts) / total
    entropy = -sum((c/total) * np.log2(c/total) for c in signal_counts.values() if c > 0)
    most_common_ratio = signal_counts.most_common(1)[0][1] / total
    
    # Extract TCP metadata from events
    ttl_values = []
    window_sizes = []
    entropy_scores = []
    tcp_timestamp_count = 0
    
    for event in events:
        metadata = event.get('Metadata', {})
        if 'ttl' in metadata:
            ttl_values.append(metadata['ttl'])
        if 'window_size' in metadata:
            window_sizes.append(metadata['window_size'])
        if 'entropy_score' in metadata:
            entropy_scores.append(metadata['entropy_score'])
        if 'tcp_timestamp' in metadata:
            tcp_timestamp_count += 1
    
    ttl_avg = float(np.mean(ttl_values)) if ttl_values else 0
    window_avg = float(np.mean(window_sizes)) if window_sizes else 0
    entropy_avg = float(np.mean(entropy_scores)) if entropy_scores else 0
    
    # Extract HTTP status codes from metadata
    status_codes = []
    for event in events:
        metadata = event.get('Metadata', {})
        if 'status_code' in metadata and metadata['status_code'] > 0:
            status_codes.append(metadata['status_code'])
    
    # Status code statistics
    status_4xx_count = sum(1 for s in status_codes if 400 <= s < 500)
    status_5xx_count = sum(1 for s in status_codes if 500 <= s < 600)
    status_4xx_ratio = status_4xx_count / len(status_codes) if status_codes else 0
    status_5xx_ratio = status_5xx_count / len(status_codes) if status_codes else 0
    status_diversity = len(set(status_codes)) / len(status_codes) if status_codes else 0
    status_error_ratio = (status_4xx_count + status_5xx_count) / len(status_codes) if status_codes else 0
    
    return {
        'signal_diversity': diversity,
        'signal_entropy': entropy,
        'signal_most_common_ratio': most_common_ratio,
        'signal_unique_count': len(signal_counts),
        'signal_high_freq_count': signal_counts.get('high_frequency', 0),
        'signal_path_enum_count': signal_counts.get('path_seq_ids', 0),
        'signal_missing_header_count': signal_counts.get('missing_accept_language', 0),
        'signal_clock_skew_count': signal_counts.get('clock_skew_anomaly', 0),
        'signal_entropy_low_count': signal_counts.get('entropy_low', 0),
        'signal_threat_score_count': signal_counts.get('high_threat_score', 0),
        'signal_ua_suspicious_count': signal_counts.get('ua_suspicious', 0),
        'signal_excessive_404_count': signal_counts.get('excessive_404', 0),
        'signal_excessive_403_count': signal_counts.get('excessive_403', 0),
        'signal_error_burst_count': signal_counts.get('error_burst', 0),
        'signal_scanner_indicators': signal_counts.get('excessive_404', 0) + signal_counts.get('excessive_403', 0) + signal_counts.get('error_burst', 0),
        'signal_tcp_ttl_avg': ttl_avg,
        'signal_tcp_window_avg': window_avg / 65535.0 if window_avg > 0 else 0,  # Normalized
        'signal_tcp_entropy_avg': entropy_avg / 100.0 if entropy_avg > 0 else 0,  # Normalized
        'signal_tcp_timestamp_ratio': tcp_timestamp_count / total if total > 0 else 0,
        'signal_status_4xx_count': status_4xx_count,
        'signal_status_5xx_count': status_5xx_count,
        'signal_status_4xx_ratio': status_4xx_ratio,
        'signal_status_5xx_ratio': status_5xx_ratio,
        'signal_status_diversity': status_diversity,
        'signal_status_error_ratio': status_error_ratio,
    }


def extract_behavioral_features(pre_events: List[Dict], post_events: List[Dict]) -> Dict:
    """Extract behavior change features (10 features)."""
    pre_temp = extract_temporal_features(pre_events)
    post_temp = extract_temporal_features(post_events)
    
    rate_change = post_temp['temporal_requests_per_sec'] - pre_temp['temporal_requests_per_sec']
    rate_ratio = post_temp['temporal_requests_per_sec'] / pre_temp['temporal_requests_per_sec'] if pre_temp['temporal_requests_per_sec'] > 0 else 1
    burst_change = post_temp['temporal_burst_coef'] - pre_temp['temporal_burst_coef']
    
    return {
        'behavior_pre_rate': pre_temp['temporal_requests_per_sec'],
        'behavior_post_rate': post_temp['temporal_requests_per_sec'],
        'behavior_rate_change': rate_change,
        'behavior_rate_ratio': rate_ratio,
        'behavior_burst_change': burst_change,
        'behavior_changed_significantly': int(abs(rate_ratio - 1) > 0.5),
        'behavior_pre_events': len(pre_events),
        'behavior_post_events': len(post_events),
        'behavior_event_ratio': len(post_events) / len(pre_events) if len(pre_events) > 0 else 1,
        'behavior_slowed_down': int(rate_ratio < 0.5),
    }


def extract_fingerprint_features(events: List[Dict], detection: Dict) -> Dict:
    """Extract TLS/HTTP fingerprint features (10 features)."""
    ja4_values = []
    ja4h_values = []
    ja4t_values = []
    
    # Collect from events
    for event in events:
        if 'JA4' in event and event['JA4']:
            ja4_values.append(event['JA4'])
        if 'JA4H' in event and event['JA4H']:
            ja4h_values.append(event['JA4H'])
        if 'JA4T' in event and event['JA4T']:
            ja4t_values.append(event['JA4T'])
        
        # Also check metadata
        metadata = event.get('Metadata', {})
        if 'ja4' in metadata and metadata['ja4']:
            ja4_values.append(metadata['ja4'])
        if 'ja4h' in metadata and metadata['ja4h']:
            ja4h_values.append(metadata['ja4h'])
        if 'ja4t' in metadata and metadata['ja4t']:
            ja4t_values.append(metadata['ja4t'])
    
    # Also get from detection
    if detection.get('ja4'):
        ja4_values.append(detection['ja4'])
    if detection.get('ja4h'):
        ja4h_values.append(detection['ja4h'])
    if detection.get('ja4t'):
        ja4t_values.append(detection['ja4t'])
    
    # Calculate diversity and consistency
    ja4_diversity = len(set(ja4_values)) / len(ja4_values) if ja4_values else 0
    ja4h_diversity = len(set(ja4h_values)) / len(ja4h_values) if ja4h_values else 0
    ja4t_diversity = len(set(ja4t_values)) / len(ja4t_values) if ja4t_values else 0
    
    return {
        'fingerprint_ja4_present': int(bool(ja4_values)),
        'fingerprint_ja4h_present': int(bool(ja4h_values)),
        'fingerprint_ja4t_present': int(bool(ja4t_values)),
        'fingerprint_ja4_diversity': ja4_diversity,
        'fingerprint_ja4h_diversity': ja4h_diversity,
        'fingerprint_ja4t_diversity': ja4t_diversity,
        'fingerprint_ja4_count': len(set(ja4_values)),
        'fingerprint_ja4h_count': len(set(ja4h_values)),
        'fingerprint_ja4t_count': len(set(ja4t_values)),
        'fingerprint_all_consistent': int(ja4_diversity == 0 and ja4h_diversity == 0 and ja4t_diversity == 0) if ja4_values or ja4h_values or ja4t_values else 0,
    }


def extract_advanced_features_from_session(session: Dict) -> Dict:
    """Extract all features from session."""
    detection = session.get('Detection', {})
    pre_events = session.get('PreEvents', [])
    post_events = session.get('PostEvents', [])
    all_events = pre_events + post_events
    
    features = {}
    
    # Temporal (25 features)
    features.update(extract_temporal_features(all_events))
    
    # Path (20 features)
    features.update(extract_path_features(all_events))
    
    # Header (25 features)
    features.update(extract_header_features(all_events))
    
    # Signal (25 features - includes HTTP error tracking + status code analysis)
    features.update(extract_signal_features(all_events))
    
    # Fingerprint (10 features - JA4/JA4H/JA4T analysis)
    features.update(extract_fingerprint_features(all_events, detection))
    
    # Behavioral (10 features)
    features.update(extract_behavioral_features(pre_events, post_events))
    
    # Original detection (5 features)
    features['original_confidence'] = detection.get('confidence', 0)
    features['original_signal_count'] = detection.get('signal_count', 0)
    features['original_would_block'] = int(detection.get('would_block', False))
    features['original_threat_score'] = detection.get('threat_score', 0)
    features['original_ml_confidence'] = detection.get('ml_confidence', 0)
    
    # Label
    label = session.get('Label', '')
    features['label'] = 'bot' if label in ['tp', 'fn', 'bot'] else 'human' if label in ['fp', 'tn', 'human', 'verified_bot'] else ''
    
    # Metadata
    features['ip'] = session.get('IP', '')
    features['session_id'] = session.get('SessionID', '')
    
    return features


def main():
    parser = argparse.ArgumentParser(description="Extract advanced features")
    parser.add_argument('--sessions', default='/var/cache/packetyeeter/sessions')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    
    # Load sessions
    sessions_dir = Path(args.sessions)
    files = glob.glob(str(sessions_dir / "recording-*.jsonl"))
    
    if not files:
        print(f"No session files found in {args.sessions}")
        return
    
    print(f"Processing {len(files)} session files...")
    
    all_features = []
    processed = 0
    skipped = 0
    
    for i, filepath in enumerate(sorted(files)):
        if i % 50 == 0:
            print(f"Processing file {i+1}/{len(files)}...")
        
        with open(filepath, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        session = json.loads(line)
                        
                        # Quick label check before expensive feature extraction
                        label = session.get('Label', '')
                        if not label or label == '':
                            skipped += 1
                            continue
                        
                        features = extract_advanced_features_from_session(session)
                        
                        if features['label']:
                            all_features.append(features)
                            processed += 1
                            if processed % 10 == 0:
                                print(f"  Extracted {processed} labeled sessions...")
                        else:
                            skipped += 1
                    except Exception as e:
                        print(f"Warning: {e}")
                        skipped += 1
    
    print(f"\nProcessed {processed} sessions with labels")
    print(f"Skipped {skipped} sessions without labels")
    
    if not all_features:
        print("No labeled sessions found!")
        return
    
    # Write output
    with open(args.output, 'w') as f:
        for features in all_features:
            f.write(json.dumps(features) + '\n')
    
    feature_count = len(all_features[0]) - 3  # Exclude label, ip, session_id
    print(f"\n✓ Wrote {len(all_features)} feature vectors with {feature_count} features each")
    
    # Label distribution
    labels = Counter(f['label'] for f in all_features)
    print(f"\nLabel distribution:")
    for label, count in labels.items():
        print(f"  {label}: {count} ({count/len(all_features)*100:.1f}%)")


if __name__ == '__main__':
    main()
