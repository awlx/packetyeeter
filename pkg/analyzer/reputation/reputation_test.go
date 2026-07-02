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
