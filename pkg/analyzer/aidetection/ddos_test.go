package aidetection

import (
	"testing"
	"time"
)

func TestIsDDoSPatternRequireHighFreq(t *testing.T) {
	e := New(Config{
		DDoSIncompleteThreshold: 100,
		DDoSPatternThreshold:    100,
		DDoSTotalThreshold:      200,
		DDoSRequireHighFreq:     true,
	})

	// 120 incomplete, low weight => should NOT trigger when requireHighFreq=true and below flood thresholds
	signals := make([]Signal, 120)
	for i := range signals {
		signals[i] = Signal{Type: SignalIncompleteHandshake, Weight: 10}
	}
	if ok, _ := e.isDDoSPattern(signals, 0); ok {
		t.Fatalf("expected no ddos for low-weight incomplete handshakes")
	}

	// Heavy flood should trigger even without highfreq when weight exceeds thresholds
	for i := range signals {
		signals[i] = Signal{Type: SignalIncompleteHandshake, Weight: 2001}
	}
	if ok, _ := e.isDDoSPattern(signals, 0); !ok {
		t.Fatalf("expected ddos for heavy incomplete handshakes")
	}
}

func TestIsDDoSPatternDisabled(t *testing.T) {
	e := New(Config{EnableDDoSCategory: false})
	signals := make([]Signal, 600)
	for i := range signals {
		signals[i] = Signal{Type: SignalHighFrequency}
	}
	if ok, _ := e.isDDoSPattern(signals, 0); ok {
		t.Fatalf("expected ddos detection disabled")
	}
}

type testHandler struct{ ch chan DetectionEvent }

func (h testHandler) HandleDetection(ev DetectionEvent) { h.ch <- ev }

func TestWeakFloodSignalsIgnored(t *testing.T) {
	e := New(Config{Workers: 1, BufferSize: 100, WarmupPeriod: 0, StaticThreshold: 3, DDoSMinFloodWeight: 50})
	ch := make(chan DetectionEvent, 1)
	e.RegisterDetectionHandler(testHandler{ch})
	e.Start()
	defer e.Stop()

	// Emit low-weight flood signals (total flood weight = 5 < 50)
	e.EmitSignal(Signal{Type: SignalUDPFlood, Source: SourceUDP, Weight: 1})
	e.EmitSignal(Signal{Type: SignalICMPFlood, Source: SourceICMP, Weight: 3})
	e.EmitSignal(Signal{Type: SignalUDPFlood, Source: SourceUDP, Weight: 1})

	select {
	case <-ch:
		t.Fatalf("expected no detection for weak flood signals")
	case <-time.After(200 * time.Millisecond):
	}
}
