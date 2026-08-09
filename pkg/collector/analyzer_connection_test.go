package collector

import (
	"testing"
	"time"
)

func TestAnalyzerReconnectBackoffGrowsForUnstableStreams(t *testing.T) {
	delay, next := analyzerReconnectBackoff(time.Second, time.Millisecond)
	if delay != time.Second || next != 2*time.Second {
		t.Fatalf("first unstable reconnect = (%v, %v), want (1s, 2s)", delay, next)
	}

	delay, next = analyzerReconnectBackoff(next, time.Millisecond)
	if delay != 2*time.Second || next != 4*time.Second {
		t.Fatalf("second unstable reconnect = (%v, %v), want (2s, 4s)", delay, next)
	}

	delay, next = analyzerReconnectBackoff(analyzerReconnectMax, time.Millisecond)
	if delay != analyzerReconnectMax || next != analyzerReconnectMax {
		t.Fatalf("capped reconnect = (%v, %v), want (%v, %v)",
			delay, next, analyzerReconnectMax, analyzerReconnectMax)
	}
}

func TestAnalyzerReconnectBackoffResetsAfterStableStream(t *testing.T) {
	delay, next := analyzerReconnectBackoff(analyzerReconnectMax, analyzerConnectionStable)
	if delay != analyzerReconnectInitial || next != 2*analyzerReconnectInitial {
		t.Fatalf("stable reconnect = (%v, %v), want (1s, 2s)", delay, next)
	}
}
