package patterns

import "testing"

// TestDetectWindowAnomaly_StableRealisticWindowIsNotFlagged verifies that a
// single source consistently advertising the same, plausible TCP window
// size is NOT treated as anomalous. This is normal behavior for a real TCP
// stack (the value comes from that client's OS/socket-buffer configuration
// and won't change unless receive-buffer usage does) - production traffic
// showed ordinary VPS/hosting-provider clients getting false-positive
// flagged here purely because their stable window value wasn't in a
// hardcoded three-item allowlist.
func TestDetectWindowAnomaly_StableRealisticWindowIsNotFlagged(t *testing.T) {
	pt := &PatternTracker{}
	windows := make([]uint16, 10)
	for i := range windows {
		windows[i] = 25765 // a real, if uncommon, window value seen in production
	}

	if pt.detectWindowAnomaly(windows) {
		t.Fatalf("expected a stable, plausible window size to not be flagged as anomalous")
	}
}

// TestDetectWindowAnomaly_KnownCommonValuesNotFlagged is a regression guard
// for the previously-hardcoded allowlist values.
func TestDetectWindowAnomaly_KnownCommonValuesNotFlagged(t *testing.T) {
	pt := &PatternTracker{}
	for _, v := range []uint16{65535, 29200, 14600} {
		windows := make([]uint16, 10)
		for i := range windows {
			windows[i] = v
		}
		if pt.detectWindowAnomaly(windows) {
			t.Fatalf("expected common window value %d to not be flagged as anomalous", v)
		}
	}
}

// TestDetectWindowAnomaly_ZeroWindowIsFlagged verifies a stalled/malformed
// connection (window size 0 on every packet) is still caught.
func TestDetectWindowAnomaly_ZeroWindowIsFlagged(t *testing.T) {
	pt := &PatternTracker{}
	windows := make([]uint16, 10) // all zero value
	if !pt.detectWindowAnomaly(windows) {
		t.Fatalf("expected an all-zero window size to be flagged as anomalous")
	}
}

// TestDetectWindowAnomaly_TinyWindowIsFlagged verifies a suspiciously small
// stable window (characteristic of bare raw-socket scanning tools) is
// still caught.
func TestDetectWindowAnomaly_TinyWindowIsFlagged(t *testing.T) {
	pt := &PatternTracker{}
	windows := make([]uint16, 10)
	for i := range windows {
		windows[i] = 64 // far below any real OS network stack default
	}
	if !pt.detectWindowAnomaly(windows) {
		t.Fatalf("expected a tiny stable window size to be flagged as anomalous")
	}
}

// TestDetectWindowAnomaly_VaryingWindowsNotFlagged verifies windows that
// vary naturally (e.g. due to window scaling and changing receive-buffer
// occupancy) are not flagged just because they're not identical.
func TestDetectWindowAnomaly_VaryingWindowsNotFlagged(t *testing.T) {
	pt := &PatternTracker{}
	windows := []uint16{25765, 25760, 25770, 25765, 25700, 25765, 25765, 25765, 25765, 25710}
	if pt.detectWindowAnomaly(windows) {
		t.Fatalf("expected naturally varying window sizes to not be flagged as anomalous")
	}
}

// TestDetectWindowAnomaly_TooFewSamplesNotFlagged verifies the function
// requires at least 10 samples before making a determination.
func TestDetectWindowAnomaly_TooFewSamplesNotFlagged(t *testing.T) {
	pt := &PatternTracker{}
	windows := []uint16{0, 0, 0, 0, 0} // all-zero but too few samples
	if pt.detectWindowAnomaly(windows) {
		t.Fatalf("expected fewer than 10 samples to never be flagged")
	}
}
