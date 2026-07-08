package reputation

import (
	"fmt"
	"math"
	"testing"
	"time"
)

func TestPenalizeASNScaling(t *testing.T) {
	e := New(time.Hour, 1.0, 100)
	asn := "AS123"
	// Observe 100 unique IPs
	for i := 0; i < 100; i++ {
		e.ObserveIP(asn, fmt.Sprintf("1.1.1.%d", i))
	}

	// Penalize 10 offenders among observed IPs
	score := 0.0
	expected := 0.0
	for i := 0; i < 10; i++ {
		score = e.PenalizeASN(asn, fmt.Sprintf("1.1.1.%d", i), 10.0, "test")
		ratio := float64(i+1) / 100.0
		dampen := 1.0 / math.Sqrt(float64(i+1))
		expected += 10.0 * ratio * dampen
	}
	total, offenders := e.GetASNStats(asn)
	t.Logf("total=%d offenders=%d score=%.4f", total, offenders, score)
	if math.Abs(score-expected) > 1e-6 {
		t.Fatalf("expected cumulative score %.4f got %.4f", expected, score)
	}
	if total != 100 || offenders != 10 {
		t.Fatalf("expected stats total=100 offenders=10 got total=%d offenders=%d", total, offenders)
	}
}

func TestPenalizeASNNoObservedFallback(t *testing.T) {
	e := New(time.Hour, 1.0, 100)
	score := e.PenalizeASN("AS999", "2.2.2.2", 10.0, "test")
	expected := 0.2 // base_weight * (1 offender / softened total=50)
	if math.Abs(score-expected) > 1e-6 {
		t.Fatalf("expected score %.4f got %.4f", expected, score)
	}
}

func TestDecayExpiresEntriesPastMaxAge(t *testing.T) {
	e := New(time.Hour, 0.95, 100)
	e.SetMaxEntryAge(time.Minute)
	e.Penalize("203.0.113.10", TypeIP, 20, "test")

	entry := e.entries[string(TypeIP)+":203.0.113.10"]
	entry.LastSeen = time.Now().Add(-2 * time.Minute)
	e.decay()

	if score := e.GetScore("203.0.113.10", TypeIP); score != 0 {
		t.Fatalf("expected expired entry to be removed, got score %.2f", score)
	}
}

func TestDecayHalfLifeDocumentsConfiguredForgiveness(t *testing.T) {
	interval := 5 * time.Minute
	e := New(interval, 0.95, 100)

	halfLife := e.DecayHalfLife(interval)
	expected := time.Duration(math.Log(0.5) / math.Log(0.95) * float64(interval))
	if halfLife != expected {
		t.Fatalf("expected half-life %s got %s", expected, halfLife)
	}
	if halfLife <= time.Hour || halfLife >= 75*time.Minute {
		t.Fatalf("expected 5m/0.95 decay half-life to be around 68 minutes, got %s", halfLife)
	}
}

// TestRecordSignalMatchesIndividualCalls verifies that the single-lock
// RecordSignal batch method produces the exact same scores and ASN
// seen/offender bookkeeping as the equivalent sequence of
// Penalize/ObserveIP/PenalizeASN/Penalize calls it replaces in the
// AI-engine hot path.
func TestRecordSignalMatchesIndividualCalls(t *testing.T) {
	newEngines := func() (individual, combined *Engine) {
		return New(time.Hour, 1.0, 100), New(time.Hour, 1.0, 100)
	}

	asn := "AS64500"
	ja4h := "t13d1516h2_abcd"
	ips := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}

	individual, combined := newEngines()

	var wantIPScore, wantASNScore float64
	for _, ip := range ips {
		wantIPScore = individual.Penalize(ip, TypeIP, 5.0, "test")
		individual.ObserveIP(asn, ip)
		wantASNScore = individual.PenalizeASN(asn, ip, 1.25, "test")
		individual.Penalize(ja4h, TypeJA4, 3.0, "test")
	}

	var gotIPScore, gotASNScore float64
	for _, ip := range ips {
		gotIPScore, gotASNScore = combined.RecordSignal(ip, 5.0, asn, 1.25, ja4h, 3.0, "test")
	}

	if gotIPScore != wantIPScore {
		t.Fatalf("IP score mismatch: RecordSignal=%.4f individual calls=%.4f", gotIPScore, wantIPScore)
	}
	if gotASNScore != wantASNScore {
		t.Fatalf("ASN score mismatch: RecordSignal=%.4f individual calls=%.4f", gotASNScore, wantASNScore)
	}

	wantTotal, wantOffenders := individual.GetASNStats(asn)
	gotTotal, gotOffenders := combined.GetASNStats(asn)
	if wantTotal != gotTotal || wantOffenders != gotOffenders {
		t.Fatalf("ASN stats mismatch: RecordSignal total=%d offenders=%d, individual calls total=%d offenders=%d",
			gotTotal, gotOffenders, wantTotal, wantOffenders)
	}

	for _, ip := range ips {
		if got, want := combined.GetScore(ip, TypeIP), individual.GetScore(ip, TypeIP); got != want {
			t.Fatalf("IP %s score mismatch: got %.4f want %.4f", ip, got, want)
		}
	}
	if got, want := combined.GetScore(ja4h, TypeJA4), individual.GetScore(ja4h, TypeJA4); got != want {
		t.Fatalf("JA4H score mismatch: got %.4f want %.4f", got, want)
	}
}

// TestRecordSignalSkipsEmptyKeys verifies RecordSignal is a no-op for any
// key that's empty, matching the guards in Penalize/ObserveIP/PenalizeASN.
func TestRecordSignalSkipsEmptyKeys(t *testing.T) {
	e := New(time.Hour, 1.0, 100)

	ipScore, asnScore := e.RecordSignal("", 5.0, "", 1.25, "", 3.0, "test")
	if ipScore != 0 || asnScore != 0 {
		t.Fatalf("expected zero scores for empty keys, got ip=%.4f asn=%.4f", ipScore, asnScore)
	}
	if len(e.entries) != 0 {
		t.Fatalf("expected no entries recorded for empty keys, got %d", len(e.entries))
	}
}
