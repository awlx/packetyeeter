package aidetection

import (
	"testing"
	"time"
)

func TestOnCampaignReceivesEveryEmittedDetection(t *testing.T) {
	var got []CampaignDetection
	engine := New(Config{Campaign: testCampaignConfig(), OnCampaign: func(d CampaignDetection) {
		got = append(got, d)
	}})

	// evaluateCampaigns evaluates at wall-clock time.
	recordDNSCampaignSignals(engine.campaigns, time.Now().Add(-10*time.Second), 1, 8)
	engine.evaluateCampaigns()

	if len(got) != 1 {
		t.Fatalf("OnCampaign called %d times, want 1", len(got))
	}
	if got[0].DstPrefix() != "203.0.113.0/24" {
		t.Fatalf("DstPrefix = %q", got[0].DstPrefix())
	}
	if got[0].Baseline.Protocol != "udp" || got[0].Baseline.DstPortBucket != "53" {
		t.Fatalf("baseline not attached: %+v", got[0].Baseline)
	}
	if engine.latestDetections["campaign:"+got[0].ID] == nil {
		t.Fatal("hook ran but the detection was not handled as before")
	}
}

func TestCampaignDetectionDstPrefix(t *testing.T) {
	for key, want := range map[string]string{
		"vector=udp_flood|source=udp|collector=a|dest_subnet=2001:db8::/64": "2001:db8::/64",
		"vector=udp_flood|source=udp|collector=a|dest_subnet=any":           "",
		"vector=udp_flood|source=udp|collector=a|dest_subnet=unknown":       "",
		"": "",
	} {
		if got := (CampaignDetection{Key: key}).DstPrefix(); got != want {
			t.Errorf("DstPrefix(%q) = %q, want %q", key, got, want)
		}
	}
}
