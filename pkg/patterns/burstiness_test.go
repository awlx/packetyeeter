package patterns

import (
	"testing"
	"time"
)

// burstinessFromTimings must measure the distribution of inter-connection gaps
// (coefficient of variation), not merely how many samples exist. These tests
// lock in that contract and are a regression guard for the old
// `len(PacketTimings) > 5` heuristic.

func TestBurstinessFromTimings_EvenlyPacedIsNotBursty(t *testing.T) {
	// 20 identical 100ms gaps: perfectly regular, CV = 0.
	timings := make([]time.Duration, 20)
	for i := range timings {
		timings[i] = 100 * time.Millisecond
	}
	if burstinessFromTimings(timings) {
		t.Fatal("evenly-paced timings should not be classified as bursty")
	}
}

func TestBurstinessFromTimings_ManyRegularSamplesNotBursty(t *testing.T) {
	// Regression for the old count>5 heuristic: many samples that are NOT
	// clustered must not be flagged bursty just because there are lots of them.
	timings := make([]time.Duration, 50)
	for i := range timings {
		// Small natural jitter around 100ms (CV well below 1).
		timings[i] = time.Duration(95+i%10) * time.Millisecond
	}
	if burstinessFromTimings(timings) {
		t.Fatal("many mildly-jittery samples should not be classified as bursty")
	}
}

func TestBurstinessFromTimings_ClusteredIsBursty(t *testing.T) {
	// Tight clusters separated by long idle gaps: high CV -> bursty.
	timings := []time.Duration{
		1 * time.Millisecond, 1 * time.Millisecond, 1 * time.Millisecond,
		5 * time.Second,
		1 * time.Millisecond, 1 * time.Millisecond, 1 * time.Millisecond,
		5 * time.Second,
		1 * time.Millisecond, 1 * time.Millisecond,
	}
	if !burstinessFromTimings(timings) {
		t.Fatal("clustered timings with long idle gaps should be classified as bursty")
	}
}

func TestBurstinessFromTimings_TooFewSamplesNotBursty(t *testing.T) {
	if burstinessFromTimings([]time.Duration{1 * time.Millisecond, 5 * time.Second}) {
		t.Fatal("fewer than 3 gaps should not be classified as bursty")
	}
}
