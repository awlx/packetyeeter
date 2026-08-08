package aidetection

import (
	"net"
	"testing"
	"time"

	"PacketYeeter/pkg/analyzer/reputation"
)

// strongLegitStub is an ML model that always claims traffic is strongly
// legitimate, the case that must NOT be able to erase deterministic evidence.
type strongLegitStub struct{}

func (strongLegitStub) Predict(MLFeatures) MLPredictionResult {
	return MLPredictionResult{IsBot: false, Confidence: 0.99, BotProbability: 0.01, ModelTier: "onnx"}
}
func (strongLegitStub) Train(MLFeatures, bool) error { return nil }

// #66.1: a source that has crossed the reputation ban threshold is accumulated
// deterministic evidence. Under the default ML integration, a strong-legitimate
// ML verdict fed sparse inputs must not be able to permanently veto it: the
// reputation-bad source must reach a block candidate while an identical clean
// source does not.
func TestReputationBadActorReachesBlockDespiteStrongLegitML(t *testing.T) {
	rep := reputation.New(time.Hour, 0.95, 5.0) // ban threshold 5, slow decay
	badIP := net.ParseIP("203.0.113.201")
	rep.Penalize(badIP.String(), reputation.TypeIP, 50.0, "test setup") // well over threshold

	e := New(Config{
		Workers:             1,
		BufferSize:          100,
		WarmupPeriod:        time.Nanosecond,
		StaticThreshold:     3,
		ConfidenceThreshold: 0.8,
		Reputation:          rep,
		MLModel:             strongLegitStub{},
	})
	ch := make(chan DetectionEvent, 1)
	e.RegisterDetectionHandler(testHandler{ch})
	time.Sleep(5 * time.Millisecond)

	// A low-severity mix that, on its own with a strong-legit ML verdict, is
	// capped below the block threshold. The passed initial confidence (0.85)
	// only clears the low-severity pre-filter; handleDetection recomputes the
	// real rule confidence from the signals + reputation.
	mkSignals := func(ip net.IP) []Signal {
		s := []Signal{{Type: SignalWindowAnomaly, Source: SourceTCP, Weight: 5, IP: ip}}
		for i := 0; i < 4; i++ {
			s = append(s, Signal{Type: SignalMissingAcceptLang, Source: SourceSPOE, Weight: 0.5, IP: ip})
		}
		return s
	}

	e.handleDetection("ip:"+badIP.String(), mkSignals(badIP), 0, 0.85, 0)
	select {
	case ev := <-ch:
		if !ev.WouldBlock {
			t.Fatalf("reputation-bad actor should reach a block candidate despite strong-legit ML; confidence=%.4f", ev.Confidence)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected a detection event for the reputation-bad actor")
	}

	// Control: an identical signal set from a clean IP must NOT block, proving
	// the block came from the reputation evidence and not the signals alone.
	cleanIP := net.ParseIP("203.0.113.202")
	e.handleDetection("ip:"+cleanIP.String(), mkSignals(cleanIP), 0, 0.85, 0)
	select {
	case ev := <-ch:
		if ev.WouldBlock {
			t.Fatalf("clean IP with the same signals must not block under strong-legit ML: %+v", ev)
		}
	case <-time.After(300 * time.Millisecond):
		// No event is also an acceptable "did not block" outcome.
	}
}

// #70.1: a confirmed known-bot exact JA4H match is deterministic evidence that a
// strong-legitimate ML verdict must not erase. A non-bot JA4H match and an exact
// JA4 (not JA4H) match are NOT deterministic and must remain vetoable, so a
// legitimate client that merely matches a catalogued/collided fingerprint is not
// blocked. Each set carries a lone JA4H-bot-match signal (whose high-severity
// bonus alone leaves rule confidence below 0.80) plus two low-severity signals,
// so the outcome is decided by the deterministic floor, not raw signal weight.
func TestKnownBotExactJA4HFloorsConfidenceButOthersDoNot(t *testing.T) {
	e := New(Config{
		Workers:             1,
		BufferSize:          100,
		WarmupPeriod:        time.Nanosecond,
		StaticThreshold:     3,
		ConfidenceThreshold: 0.8,
		MLModel:             strongLegitStub{},
	})
	ch := make(chan DetectionEvent, 1)
	e.RegisterDetectionHandler(testHandler{ch})
	time.Sleep(5 * time.Millisecond)

	mkSignals := func(ip net.IP, md map[string]interface{}) []Signal {
		return []Signal{
			{Type: SignalJA4HBotMatch, Source: SourceFingerprint, Weight: 30, IP: ip, JA4H: "ge11nn020000_deadbeefcafe", Metadata: md},
			{Type: SignalMissingAcceptLang, Source: SourceSPOE, Weight: 0.5, IP: ip},
			{Type: SignalNoCookies, Source: SourceSPOE, Weight: 0.5, IP: ip},
		}
	}

	// Confirmed known-bot exact JA4H: deterministic -> floored -> blocks.
	botIP := net.ParseIP("203.0.113.211")
	e.handleDetection("ip:"+botIP.String(), mkSignals(botIP, map[string]interface{}{"known_bot": true, "fp_type": "ja4h", "match_type": "exact"}), 0, 0.7, 0)
	select {
	case ev := <-ch:
		if !ev.WouldBlock {
			t.Fatalf("confirmed known-bot exact JA4H match should block despite strong-legit ML; confidence=%.4f", ev.Confidence)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected a detection event for the known-bot exact JA4H match")
	}

	// Non-bot exact JA4H: not deterministic -> vetoable -> no block.
	nonBotIP := net.ParseIP("203.0.113.212")
	e.handleDetection("ip:"+nonBotIP.String(), mkSignals(nonBotIP, map[string]interface{}{"known_bot": false, "fp_type": "ja4h", "match_type": "exact"}), 0, 0.7, 0)
	select {
	case ev := <-ch:
		if ev.WouldBlock {
			t.Fatalf("a non-bot exact JA4H match must remain vetoable by strong-legit ML: %+v", ev)
		}
	case <-time.After(300 * time.Millisecond):
	}

	// Exact JA4 (not JA4H): not deterministic -> vetoable -> no block.
	ja4IP := net.ParseIP("203.0.113.213")
	e.handleDetection("ip:"+ja4IP.String(), mkSignals(ja4IP, map[string]interface{}{"known_bot": true, "fp_type": "ja4", "match_type": "exact"}), 0, 0.7, 0)
	select {
	case ev := <-ch:
		if ev.WouldBlock {
			t.Fatalf("an exact JA4 (not JA4H) match must remain vetoable by strong-legit ML: %+v", ev)
		}
	case <-time.After(300 * time.Millisecond):
	}
}
