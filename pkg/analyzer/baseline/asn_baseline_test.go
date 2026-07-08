package baseline

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestRecordAndCalculateAnomaly_RoundTrip verifies that observations
// recorded for an ASN are visible to CalculateAnomaly once enough of them
// have been recorded, exercising the shard lookup on both the write and
// read paths for the same key.
func TestRecordAndCalculateAnomaly_RoundTrip(t *testing.T) {
	bc := NewBaselineCalibrator(Config{MinObservations: 5, RetentionPeriod: time.Hour, CleanupInterval: time.Hour})

	for i := 0; i < 10; i++ {
		bc.RecordObservation("AS64500", ObservationData{TTL: 64, WindowSize: 65535})
	}

	anomaly := bc.CalculateAnomaly("AS64500", ObservationData{TTL: 64, WindowSize: 65535})
	if !anomaly.IsBaselineValid {
		t.Fatalf("expected baseline to be valid after 10 observations >= minObservations 5")
	}
	if anomaly.IsAnomalous() {
		t.Fatalf("expected matching TTL/window observation to not be anomalous, got MaxZScore=%v", anomaly.MaxZScore)
	}
}

// TestCalculateAnomaly_UnknownASNNotValid ensures an ASN with no recorded
// observations reports an invalid (not-yet-calibrated) baseline rather than
// panicking or returning a false positive anomaly.
func TestCalculateAnomaly_UnknownASNNotValid(t *testing.T) {
	bc := NewBaselineCalibrator(DefaultConfig())
	anomaly := bc.CalculateAnomaly("AS999999", ObservationData{TTL: 64, WindowSize: 65535})
	if anomaly.IsBaselineValid {
		t.Fatalf("expected baseline to be invalid for an ASN with no observations")
	}
}

// TestGetStatsAggregatesAcrossShards verifies GetStats sums observation
// counts and calibrated-ASN counts across all shards, not just shard 0,
// by recording enough distinct ASNs that they can't all land in one shard.
func TestGetStatsAggregatesAcrossShards(t *testing.T) {
	bc := NewBaselineCalibrator(Config{MinObservations: 3, RetentionPeriod: time.Hour, CleanupInterval: time.Hour})

	const numASNs = 50
	for i := 0; i < numASNs; i++ {
		asn := fmt.Sprintf("AS%d", 10000+i)
		for j := 0; j < 3; j++ {
			bc.RecordObservation(asn, ObservationData{TTL: 64, WindowSize: 65535})
		}
	}

	calibrated, totalObs := bc.GetStats()
	if calibrated != numASNs {
		t.Fatalf("expected %d calibrated ASNs across all shards, got %d", numASNs, calibrated)
	}
	if totalObs != numASNs*3 {
		t.Fatalf("expected %d total observations across all shards, got %d", numASNs*3, totalObs)
	}
}

// TestCleanupRemovesStaleEntriesAcrossShards checks that cleanup() sweeps
// every shard (not just one) by seeding several ASNs with an already-old
// LastSeen and confirming they're all gone after a cleanup pass, while a
// fresh ASN survives.
func TestCleanupRemovesStaleEntriesAcrossShards(t *testing.T) {
	bc := NewBaselineCalibrator(Config{MinObservations: 1, RetentionPeriod: time.Hour, CleanupInterval: time.Hour})

	const numStale = 20
	for i := 0; i < numStale; i++ {
		asn := fmt.Sprintf("AS%d", 20000+i)
		bc.RecordObservation(asn, ObservationData{TTL: 64, WindowSize: 65535})
		// Force LastSeen into the past directly via the shard so cleanup
		// considers it stale, without needing to wait an hour in a test.
		shard := bc.shardFor(asn)
		shard.mu.Lock()
		shard.baselines[asn].LastSeen = time.Now().Add(-2 * time.Hour)
		shard.mu.Unlock()
	}
	bc.RecordObservation("AS30000", ObservationData{TTL: 64, WindowSize: 65535})

	bc.cleanup()

	for i := 0; i < numStale; i++ {
		asn := fmt.Sprintf("AS%d", 20000+i)
		if bc.GetBaseline(asn) != nil {
			t.Fatalf("expected stale ASN %s to be removed by cleanup", asn)
		}
	}
	if bc.GetBaseline("AS30000") == nil {
		t.Fatalf("expected fresh ASN AS30000 to survive cleanup")
	}
}

// TestConcurrentRecordAndCalculateDoesNotRace exercises many goroutines
// hammering RecordObservation/CalculateAnomaly across a spread of ASNs
// concurrently. Run with -race; this is the scenario that previously
// serialized on a single global mutex.
func TestConcurrentRecordAndCalculateDoesNotRace(t *testing.T) {
	bc := NewBaselineCalibrator(Config{MinObservations: 5, RetentionPeriod: time.Hour, CleanupInterval: time.Hour})

	var wg sync.WaitGroup
	const workers = 16
	const asnsPerWorker = 8
	const opsPerASN = 50

	for w := 0; w < workers; w++ {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := 0; a < asnsPerWorker; a++ {
				asn := fmt.Sprintf("AS%d", w*asnsPerWorker+a)
				for op := 0; op < opsPerASN; op++ {
					bc.RecordObservation(asn, ObservationData{TTL: 64, WindowSize: 65535})
					bc.CalculateAnomaly(asn, ObservationData{TTL: 64, WindowSize: 65535})
				}
			}
		}()
	}
	wg.Wait()
}
