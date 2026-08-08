package baseline

import (
	"testing"
	"time"
)

// A sustained, coherent, long-lived shift in an ASN's behavior (e.g. new egress
// hardware changing TTL) must eventually converge the baseline to the new normal
// instead of scoring the new regime as anomalous forever.
func TestRecordObservation_ConvergesToSustainedLegitimateShift(t *testing.T) {
	bc := NewBaselineCalibrator(Config{MinObservations: 21, RetentionPeriod: time.Hour, CleanupInterval: time.Hour})
	asn := "AS64510"
	base := time.Now()

	// Warm up with the old regime: TTL ~64 with small variance.
	oldTTLs := []uint8{63, 64, 65, 64, 63, 65, 64}
	for i := 0; i < 21; i++ {
		bc.RecordObservation(asn, ObservationData{TTL: oldTTLs[i%len(oldTTLs)], Timestamp: base.Add(time.Duration(i) * time.Second)})
	}

	// The new, permanent regime (TTL ~120) is anomalous against the old baseline.
	if a := bc.CalculateAnomaly(asn, ObservationData{TTL: 120}); !a.IsAnomalous() {
		t.Fatalf("expected TTL 120 to be anomalous against the old baseline, got MaxZScore=%v", a.MaxZScore)
	}

	// Sustain the new regime for well over convergenceMinDuration with well over
	// convergenceMinSamples coherent samples (10s apart -> 400*10s = ~66min).
	shiftStart := base.Add(time.Minute)
	newTTLs := []uint8{119, 120, 121, 120, 119, 121, 120}
	for i := 0; i < 400; i++ {
		ts := shiftStart.Add(time.Duration(i) * 10 * time.Second)
		bc.RecordObservation(asn, ObservationData{TTL: newTTLs[i%len(newTTLs)], Timestamp: ts})
	}

	after := bc.CalculateAnomaly(asn, ObservationData{TTL: 120})
	if after.IsAnomalous() {
		t.Fatalf("expected baseline to converge to the sustained new regime (TTL 120 no longer anomalous), got MaxZScore=%v", after.MaxZScore)
	}
}

// A shifted regime that has enough samples but has NOT persisted for
// convergenceMinDuration must NOT converge - this is the transient-attack case,
// where converging would let a burst normalize itself into the baseline.
func TestRecordObservation_DoesNotConvergeShortLivedShift(t *testing.T) {
	bc := NewBaselineCalibrator(Config{MinObservations: 21, RetentionPeriod: time.Hour, CleanupInterval: time.Hour})
	asn := "AS64511"
	base := time.Now()

	oldTTLs := []uint8{63, 64, 65, 64, 63, 65, 64}
	for i := 0; i < 21; i++ {
		bc.RecordObservation(asn, ObservationData{TTL: oldTTLs[i%len(oldTTLs)], Timestamp: base.Add(time.Duration(i) * time.Second)})
	}

	// 400 coherent samples (> convergenceMinSamples) but packed into ~400s,
	// far under convergenceMinDuration (30 min).
	shiftStart := base.Add(time.Minute)
	newTTLs := []uint8{119, 120, 121, 120, 119, 121, 120}
	for i := 0; i < 400; i++ {
		ts := shiftStart.Add(time.Duration(i) * time.Second)
		bc.RecordObservation(asn, ObservationData{TTL: newTTLs[i%len(newTTLs)], Timestamp: ts})
	}

	after := bc.CalculateAnomaly(asn, ObservationData{TTL: 120})
	if !after.IsAnomalous() {
		t.Fatalf("expected a short-lived (sub-duration) shift to remain anomalous, got MaxZScore=%v", after.MaxZScore)
	}
}

// If the new regime reverts to the old one before convergence completes, the
// candidate must be discarded so a later legitimate stat isn't corrupted.
func TestRecordObservation_RevertingRegimeDoesNotConverge(t *testing.T) {
	bc := NewBaselineCalibrator(Config{MinObservations: 21, RetentionPeriod: time.Hour, CleanupInterval: time.Hour})
	asn := "AS64512"
	base := time.Now()

	oldTTLs := []uint8{63, 64, 65, 64, 63, 65, 64}
	for i := 0; i < 21; i++ {
		bc.RecordObservation(asn, ObservationData{TTL: oldTTLs[i%len(oldTTLs)], Timestamp: base.Add(time.Duration(i) * time.Second)})
	}

	// A few anomalous samples, then a return to the old regime (resets candidate),
	// repeated. The candidate never persists long enough to adopt.
	ts := base.Add(time.Minute)
	for cycle := 0; cycle < 50; cycle++ {
		for i := 0; i < 5; i++ {
			bc.RecordObservation(asn, ObservationData{TTL: 120, Timestamp: ts})
			ts = ts.Add(time.Minute)
		}
		for i := 0; i < 5; i++ {
			bc.RecordObservation(asn, ObservationData{TTL: 64, Timestamp: ts})
			ts = ts.Add(time.Minute)
		}
	}

	after := bc.CalculateAnomaly(asn, ObservationData{TTL: 120})
	if !after.IsAnomalous() {
		t.Fatalf("expected a flapping/reverting regime to remain anomalous, got MaxZScore=%v", after.MaxZScore)
	}
}
