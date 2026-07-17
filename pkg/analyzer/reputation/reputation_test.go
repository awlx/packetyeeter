package reputation

import (
	"fmt"
	"math"
	"sync"
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

	entry := e.GetEntry("203.0.113.10")
	entry.LastSeen = time.Now().Add(-2 * time.Minute)
	e.decay()

	if score := e.GetScore("203.0.113.10", TypeIP); score != 0 {
		t.Fatalf("expected expired entry to be removed, got score %.2f", score)
	}
}

// TestDecayReconcilesASNStatsWithExpiredEntry is a regression test for a
// leak: decay() deleted aged-out entries from sh.entries but left the
// parallel sh.asnStats (Seen/Offenders IP sets) behind forever, since the
// only reconciliation lived in SetASNScoreCap, which production never
// calls. This verifies an ASN's asnStats is cleaned up in lockstep with its
// reputation Entry when the entry ages out past maxEntryAge.
func TestDecayReconcilesASNStatsWithExpiredEntry(t *testing.T) {
	e := New(time.Hour, 0.95, 100)
	e.SetMaxEntryAge(time.Minute)

	asn := "AS64500"
	e.ObserveIP(asn, "198.51.100.1")
	e.PenalizeASN(asn, "198.51.100.1", 10.0, "test")

	if total, offenders := e.GetASNStats(asn); total == 0 || offenders == 0 {
		t.Fatalf("expected asnStats to be populated before decay, got total=%d offenders=%d", total, offenders)
	}

	entry := e.GetEntry(asn)
	entry.LastSeen = time.Now().Add(-2 * time.Minute)
	e.decay()

	if score := e.GetScore(asn, TypeASN); score != 0 {
		t.Fatalf("expected expired ASN entry to be removed, got score %.2f", score)
	}
	if total, offenders := e.GetASNStats(asn); total != 0 || offenders != 0 {
		t.Fatalf("expected asnStats to be reconciled away with the expired ASN entry, got total=%d offenders=%d", total, offenders)
	}
}

// TestDecayReconcilesASNStatsWithLowScoreEntry covers the other deletion
// path in decay(): an entry whose score decays below the 0.1 cleanup
// threshold (rather than aging out by LastSeen) must also drop its
// asnStats.
func TestDecayReconcilesASNStatsWithLowScoreEntry(t *testing.T) {
	e := New(time.Hour, 0.01, 100) // aggressive decay so score falls below 0.1 in one tick

	asn := "AS64501"
	e.ObserveIP(asn, "198.51.100.2")
	e.PenalizeASN(asn, "198.51.100.2", 5.0, "test")

	if total, _ := e.GetASNStats(asn); total == 0 {
		t.Fatalf("expected asnStats to be populated before decay")
	}

	e.decay()

	if score := e.GetScore(asn, TypeASN); score != 0 {
		t.Fatalf("expected low-score ASN entry to be removed, got score %.4f", score)
	}
	if total, offenders := e.GetASNStats(asn); total != 0 || offenders != 0 {
		t.Fatalf("expected asnStats to be reconciled away with the low-score ASN entry, got total=%d offenders=%d", total, offenders)
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
	if all := e.GetAllEntries(); len(all) != 0 {
		t.Fatalf("expected no entries recorded for empty keys, got %d", len(all))
	}
}

// TestRecordSignalConcurrentAcrossShards is a regression test for the live
// production bug this sharded rewrite fixes: the analyzer's AI detection
// engine has 16 worker goroutines that each call RecordSignal synchronously
// per detection signal. Under the old single-mutex design this fully
// serialized all workers (confirmed live: AI engine queue permanently full,
// roughly half of ~1370 signals/sec silently dropped, container CPU far
// below capacity - the signature of lock contention rather than raw
// compute cost). This test hammers RecordSignal/Penalize/Reward/GetEntry
// concurrently from many goroutines across a spread of IP/ASN/JA4H keys
// and must pass under -race with no panics or data races.
func TestRecordSignalConcurrentAcrossShards(t *testing.T) {
	e := New(time.Hour, 0.98, 100)
	e.Start()
	defer e.Stop()

	const goroutines = 64
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				ip := fmt.Sprintf("10.%d.%d.%d", g%4, (g+i)%16, i%256)
				asn := fmt.Sprintf("AS%d", (g*31+i)%20)
				ja4h := fmt.Sprintf("ja4-%d", (g+i)%10)

				e.RecordSignal(ip, 2.0, asn, 5.0, ja4h, 1.0, "concurrency-test")
				e.ObserveIP(asn, ip)
				_ = e.GetScore(ip, TypeIP)
				_ = e.IsBad(asn, TypeASN)
				_ = e.GetEntry(ip)

				if i%7 == 0 {
					e.RewardIP(ip, 1.0, "concurrency-test-reward")
				}
				if i%11 == 0 {
					e.RewardASN(asn, ip, 1.0, "concurrency-test-reward")
				}
			}
		}(g)
	}
	wg.Wait()

	all := e.GetAllEntries()
	if len(all) == 0 {
		t.Fatalf("expected entries to be recorded across concurrent goroutines, got none")
	}
	bad := e.GetBadEntries()
	t.Logf("recorded %d entries, %d over ban threshold", len(all), len(bad))
}
