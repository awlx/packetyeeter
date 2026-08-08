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

// Distinct campaign keys must yield distinct IDs (same episode).
func TestStableCampaignIDDependsOnKey(t *testing.T) {
	if stableCampaignID("k1", 1) == stableCampaignID("k2", 1) {
		t.Fatal("distinct keys must yield distinct IDs")
	}
}

// The same key in a different episode must yield a distinct ID: two unrelated
// attack episodes on the same key must not be conflated under one campaign_id.
func TestStableCampaignIDDistinctAcrossEpisodes(t *testing.T) {
	if stableCampaignID("k1", 1) == stableCampaignID("k1", 2) {
		t.Fatal("same key in different episodes must yield distinct IDs")
	}
	// And identical key+episode is stable.
	if stableCampaignID("k1", 7) != stableCampaignID("k1", 7) {
		t.Fatal("same key+episode must be stable")
	}
}

// End-to-end: a campaign that fully ages out (deleted from the aggregator) and
// then recurs on the same key later is a NEW episode and must get a distinct
// campaign_id, even though the key is identical.
func TestCampaignIDDistinctAcrossEpisodesEndToEnd(t *testing.T) {
	agg := NewCampaignAggregator(testCampaignConfig())
	now := time.Date(2026, 7, 3, 9, 0, 0, 0, time.UTC)

	recordDNSCampaignSignals(agg, now, 1, 8)
	first := agg.Evaluate(now.Add(5 * time.Second))
	if len(first) != 1 {
		t.Fatalf("expected first detection, got %d", len(first))
	}
	id1 := first[0].ID

	// Advance well past Retention with an Evaluate that finds no fresh events,
	// so the first episode's campaign object is deleted from the aggregator.
	gap := now.Add(10 * time.Minute)
	if got := agg.Evaluate(gap); len(got) != 0 {
		t.Fatalf("expected the first episode to have aged out, got %d detections", len(got))
	}

	// A brand-new burst on the same key starts a new episode.
	recordDNSCampaignSignals(agg, gap, 100, 108)
	second := agg.Evaluate(gap.Add(5 * time.Second))
	if len(second) != 1 {
		t.Fatalf("expected second-episode detection, got %d", len(second))
	}
	id2 := second[0].ID

	if id1 == id2 {
		t.Fatalf("a recurrence after full expiry must get a distinct campaign_id, both were %q", id1)
	}
}
