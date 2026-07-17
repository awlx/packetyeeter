package aidetection

import (
	"testing"
	"time"
)

// A single continuous campaign must keep one campaign ID even as its window
// slides and firstSeen advances (old events age out). Previously the ID hashed
// firstSeen, so a long-lived campaign minted a new ID every cycle, breaking
// campaign_id correlation across the same attack.
func TestCampaignIDStableAcrossFirstSeenSlide(t *testing.T) {
	agg := NewCampaignAggregator(testCampaignConfig())
	now := time.Date(2026, 7, 3, 9, 0, 0, 0, time.UTC)

	recordDNSCampaignSignals(agg, now, 1, 8)
	first := agg.Evaluate(now.Add(5 * time.Second))
	if len(first) != 1 {
		t.Fatalf("expected first detection, got %d", len(first))
	}
	id1 := first[0].ID

	// Long after the window has fully turned over: batch-1 events age out so
	// firstSeen advances, while a fresh batch sustains the same campaign key.
	later := now.Add(120 * time.Second)
	recordDNSCampaignSignals(agg, later, 9, 16)
	second := agg.Evaluate(later.Add(5 * time.Second))
	if len(second) != 1 {
		t.Fatalf("expected second detection, got %d", len(second))
	}
	id2 := second[0].ID

	if id1 != id2 {
		t.Fatalf("campaign ID changed across a firstSeen slide: %q -> %q; a continuous campaign must keep one ID", id1, id2)
	}
}

// Distinct campaign keys must yield distinct IDs.
func TestStableCampaignIDDependsOnKeyOnly(t *testing.T) {
	if stableCampaignID("k1") == stableCampaignID("k2") {
		t.Fatal("distinct keys must yield distinct IDs")
	}
}
