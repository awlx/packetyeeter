package aidetection

import (
	"testing"
	"time"

	"PacketYeeter/pkg/analyzer/baseline"
)

// calibratedBaseline returns a BaselineCalibrator with a well-established
// baseline for asn (>= minObservations samples of ttl/windowSize), useful
// for testing behavior once an ASN is "calibrated".
func calibratedBaseline(t *testing.T, asn string, ttl uint8, windowSize uint16) *baseline.BaselineCalibrator {
	t.Helper()
	bc := baseline.NewBaselineCalibrator(baseline.Config{
		MinObservations: 100,
		RetentionPeriod: 7 * 24 * time.Hour,
		CleanupInterval: time.Hour,
	})
	// Alternate +/-1 around ttl/windowSize so the baseline has non-zero
	// variance - otherwise ZScore() short-circuits to 0 for a zero-stddev
	// baseline and no signal could ever be flagged anomalous.
	for i := 0; i < 200; i++ {
		delta := uint8(i % 2)
		bc.RecordObservation(asn, baseline.ObservationData{TTL: ttl - delta + 1, WindowSize: windowSize})
	}
	return bc
}

func TestASNBaselineTrustFactor_NoCalibratorConfigured(t *testing.T) {
	e := &Engine{} // asnBaseline left nil
	signal := Signal{ASN: "AS64500", Metadata: map[string]interface{}{"ttl": uint32(64), "window_size": uint32(65535)}}

	if got := e.asnBaselineTrustFactor("AS64500", signal); got != 1.0 {
		t.Fatalf("expected no dampening without a configured baseline, got %v", got)
	}
}

func TestASNBaselineTrustFactor_EmptyASN(t *testing.T) {
	e := &Engine{asnBaseline: calibratedBaseline(t, "AS64500", 64, 65535)}
	signal := Signal{Metadata: map[string]interface{}{"ttl": uint32(64), "window_size": uint32(65535)}}

	if got := e.asnBaselineTrustFactor("", signal); got != 1.0 {
		t.Fatalf("expected no dampening for empty ASN, got %v", got)
	}
}

func TestASNBaselineTrustFactor_UncalibratedASN(t *testing.T) {
	// Baseline exists but this ASN hasn't hit MinObservations yet.
	bc := baseline.NewBaselineCalibrator(baseline.DefaultConfig())
	bc.RecordObservation("AS64500", baseline.ObservationData{TTL: 64, WindowSize: 65535})
	e := &Engine{asnBaseline: bc}
	signal := Signal{ASN: "AS64500", Metadata: map[string]interface{}{"ttl": uint32(64), "window_size": uint32(65535)}}

	if got := e.asnBaselineTrustFactor("AS64500", signal); got != 1.0 {
		t.Fatalf("expected no dampening for an ASN without enough observations to calibrate, got %v", got)
	}
}

func TestASNBaselineTrustFactor_MatchesBaseline(t *testing.T) {
	e := &Engine{asnBaseline: calibratedBaseline(t, "AS64500", 64, 65535)}
	signal := Signal{ASN: "AS64500", Metadata: map[string]interface{}{"ttl": uint32(64), "window_size": uint32(65535)}}

	got := e.asnBaselineTrustFactor("AS64500", signal)
	if got != asnBaselineTrustMultiplier {
		t.Fatalf("expected dampening factor %v for a signal matching its ASN's baseline, got %v", asnBaselineTrustMultiplier, got)
	}
}

func TestASNBaselineTrustFactor_AnomalousSignalNotDampened(t *testing.T) {
	e := &Engine{asnBaseline: calibratedBaseline(t, "AS64500", 64, 65535)}
	// TTL wildly different from the calibrated baseline (64) - should read
	// as anomalous (z-score > 3) and get no dampening.
	signal := Signal{ASN: "AS64500", Metadata: map[string]interface{}{"ttl": uint32(255), "window_size": uint32(65535)}}

	if got := e.asnBaselineTrustFactor("AS64500", signal); got != 1.0 {
		t.Fatalf("expected no dampening for an anomalous signal, got %v", got)
	}
}

func TestASNBaselineTrustFactor_NoFingerprintMetadata(t *testing.T) {
	e := &Engine{asnBaseline: calibratedBaseline(t, "AS64500", 64, 65535)}
	signal := Signal{ASN: "AS64500"} // no Metadata at all

	if got := e.asnBaselineTrustFactor("AS64500", signal); got != 1.0 {
		t.Fatalf("expected no dampening when the signal carries no TTL/window size data, got %v", got)
	}
}

func TestBaselineObservationFromMetadata(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]interface{}
		wantOK   bool
	}{
		{"nil metadata", nil, false},
		{"empty metadata", map[string]interface{}{}, false},
		{"ttl only", map[string]interface{}{"ttl": uint32(64)}, true},
		{"window size only", map[string]interface{}{"window_size": uint32(65535)}, true},
		{"both fields", map[string]interface{}{"ttl": uint32(64), "window_size": uint32(65535)}, true},
		{"zero values ignored", map[string]interface{}{"ttl": uint32(0), "window_size": uint32(0)}, false},
		{"unsupported type ignored", map[string]interface{}{"ttl": "not-a-number"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := baselineObservationFromMetadata(tt.metadata)
			if ok != tt.wantOK {
				t.Fatalf("expected ok=%v, got %v", tt.wantOK, ok)
			}
		})
	}
}
