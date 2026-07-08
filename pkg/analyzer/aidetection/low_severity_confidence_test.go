package aidetection

import (
	"net"
	"testing"
	"time"
)

// TestLowSeverityOnlyComboDoesNotFastPathToHighConfidence guards against a
// production false-positive pattern found on live hosts: a client that
// simply doesn't send an Accept-Language header (extremely common for
// non-browser clients like DoH resolvers, API clients, and mobile apps)
// making many requests would accumulate dozens to hundreds of
// missing_accept_language signals plus a single generic tcp_metadata event.
// Both signal types are low-severity, but volume alone used to be enough to
// fast-path this combination straight to 0.8 rule confidence (above the
// default 0.7 block threshold) via the static-threshold branch, with no
// distinction from combinations that include a genuinely suspicious signal
// type. This test locks in that low-severity-only combinations must not
// produce a detection from a single burst with no prior history.
func TestLowSeverityOnlyComboDoesNotFastPathToHighConfidence(t *testing.T) {
	e := New(Config{Workers: 1, BufferSize: 100, WarmupPeriod: 0, StaticThreshold: 3})
	ch := make(chan DetectionEvent, 1)
	e.RegisterDetectionHandler(testHandler{ch})

	ip := net.ParseIP("203.0.113.50")
	key := "ip:" + ip.String()

	signals := []Signal{{Type: SignalTCPMetadata, Source: SourceTCP, Weight: 1, IP: ip}}
	for i := 0; i < 10; i++ {
		signals = append(signals, Signal{Type: SignalMissingAcceptLang, Source: SourceSPOE, Weight: 0.5, IP: ip})
	}

	e.evaluateWindow(map[string][]Signal{key: signals})

	select {
	case ev := <-ch:
		t.Fatalf("expected no detection for a first-seen low-severity-only combination, got %+v", ev)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestComboWithHighSeveritySignalStillFastPaths is a regression guard
// ensuring the low-severity carve-out doesn't weaken detection for
// combinations that include a genuinely suspicious signal type - those
// should still fast-path to high confidence on volume, unchanged from
// before.
func TestComboWithHighSeveritySignalStillFastPaths(t *testing.T) {
	e := New(Config{Workers: 1, BufferSize: 100, WarmupPeriod: time.Nanosecond, StaticThreshold: 3})
	ch := make(chan DetectionEvent, 1)
	e.RegisterDetectionHandler(testHandler{ch})
	time.Sleep(5 * time.Millisecond) // let the (near-zero) warmup period elapse

	ip := net.ParseIP("203.0.113.60")
	key := "ip:" + ip.String()

	// bot_ua is not in the low-severity set, so this combo is not "lowOnly"
	// and should still hit the static-threshold fast path.
	signals := []Signal{
		{Type: SignalBotUA, Source: SourceSPOE, Weight: 10, IP: ip},
		{Type: SignalMissingAcceptLang, Source: SourceSPOE, Weight: 0.5, IP: ip},
		{Type: SignalMissingAcceptLang, Source: SourceSPOE, Weight: 0.5, IP: ip},
		{Type: SignalMissingAcceptLang, Source: SourceSPOE, Weight: 0.5, IP: ip},
	}

	e.evaluateWindow(map[string][]Signal{key: signals})

	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("expected a detection for a combination including a genuinely suspicious signal type")
	}
}
