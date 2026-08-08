package aidetection

import (
	"testing"
	"time"
)

// A detected campaign must never train its own corroborating baseline, even if
// its detection reason flaps between ticks. The self-poisoning guard used to
// key on the reason, so a campaign whose reason alternated slipped past it and
// fed the baseline every evaluation. This test forces the "reason changed"
// emission path repeatedly within a single window and asserts the baseline
// accumulates at most one sample for that window.
func TestCampaignBaselineNotRetrainedByReasonFlapping(t *testing.T) {
	cfg := testCampaignConfig()
	cfg.Baseline = CampaignBaselineConfig{
		Tau:               time.Hour,
		MinSamples:        3,
		MinRate:           0.01,
		AnomalyMultiplier: 3,
		MaxKeys:           16,
	}
	agg := NewCampaignAggregator(cfg)
	now := time.Date(2026, 7, 3, 9, 0, 0, 0, time.UTC)

	recordDNSCampaignSignals(agg, now, 1, 8)

	// Find the specific-scope campaign key.
	agg.mu.Lock()
	var key string
	for k := range agg.campaigns {
		if campaignScope(k) == "specific" {
			key = k
			break
		}
	}
	agg.mu.Unlock()
	if key == "" {
		t.Fatal("no specific-scope campaign recorded")
	}

	maxSamples := 0
	// Ten evaluations all within the same 60s window; before each, force a
	// distinct lastReason so the emission dedup treats every tick as a reason
	// flap.
	for i := 0; i < 10; i++ {
		agg.mu.Lock()
		if c := agg.campaigns[key]; c != nil {
			c.lastReason = "forced_flap"
		}
		agg.mu.Unlock()

		dets := agg.Evaluate(now.Add(time.Duration(5+i) * time.Second))
		for _, d := range dets {
			if d.ID != stableCampaignIDForKey(agg, key) {
				continue
			}
			if d.Baseline.Samples > maxSamples {
				maxSamples = d.Baseline.Samples
			}
		}
	}

	if maxSamples > 1 {
		t.Fatalf("baseline accumulated %d samples within one window under reason flapping; a campaign must not train its own baseline more than once per window", maxSamples)
	}
}

// stableCampaignIDForKey resolves the current campaign_id for a key, so the test
// can match detections for the specific-scope campaign regardless of episode.
func stableCampaignIDForKey(agg *CampaignAggregator, key string) string {
	agg.mu.Lock()
	defer agg.mu.Unlock()
	if c := agg.campaigns[key]; c != nil {
		return stableCampaignID(c.key, c.episode)
	}
	return ""
}
