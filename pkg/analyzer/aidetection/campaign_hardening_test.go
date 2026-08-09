package aidetection

import (
	"net"
	"testing"
	"time"

	"PacketYeeter/pkg/analyzer/reputation"
)

// stubMLModel is a minimal MLModel used to verify that campaign detections
// route their confidence through blendMLConfidence instead of a hardcoded
// constant.
type stubMLModel struct {
	result MLPredictionResult
}

func (s *stubMLModel) Predict(features MLFeatures) MLPredictionResult {
	return s.result
}

func (s *stubMLModel) Train(features MLFeatures, isBot bool) error {
	return nil
}

func baseCampaignDetection() CampaignDetection {
	return CampaignDetection{
		ID:               "campaign-1",
		Key:              "vector=udp_flood|source=udp|collector=collector-a|dest_subnet=203.0.113.0/24",
		Vector:           SignalUDPFlood,
		Reason:           "destination_ip_breadth",
		FirstSeen:        time.Date(2026, 7, 3, 9, 0, 0, 0, time.UTC),
		LastSeen:         time.Date(2026, 7, 3, 9, 0, 30, 0, time.UTC),
		SignalCount:      40,
		TotalWeight:      40,
		DestinationIPs:   40,
		DestSubnets:      1,
		DestinationPorts: 1,
		SourceIPs:        40,
		ASNs:             2,
		Collectors:       1,
		SourceKinds:      1,
		SampleIP:         net.ParseIP("198.51.100.10"),
		SampleDestIP:     "203.0.113.10",
		SampleDstPort:    53,
		SampleASN:        "AS64500",
		SampleOrg:        "Example Org",
	}
}

// TestCampaignConfidenceNotHardcoded verifies campaign detections no longer
// use the old hardcoded 0.65 confidence: the rule-based path should vary
// with the underlying evidence, and when an ML model is configured the
// final confidence should reflect blendMLConfidence's blending behavior
// (bot-leaning ML prediction pulls confidence up toward the ML score).
func TestCampaignConfidenceNotHardcoded(t *testing.T) {
	cfg := testCampaignConfig()
	engine := New(Config{Campaign: cfg})

	weak := baseCampaignDetection()
	weak.SignalCount = cfg.MinSignals
	weak.DestinationIPs = cfg.MinDestIPs
	weak.SourceIPs = 0
	weak.ASNs = 0
	weak.Collectors = 1
	weak.SourceKinds = 1

	strong := baseCampaignDetection()

	weakConfidence := engine.campaignConfidence(weak)
	strongConfidence := engine.campaignConfidence(strong)

	if weakConfidence == 0.65 || strongConfidence == 0.65 {
		t.Fatalf("campaign confidence must not be the old hardcoded 0.65 constant: weak=%.3f strong=%.3f", weakConfidence, strongConfidence)
	}
	if !(strongConfidence > weakConfidence) {
		t.Fatalf("expected a campaign with more evidence to have higher confidence: weak=%.3f strong=%.3f", weakConfidence, strongConfidence)
	}

	// Now verify ML blending: a highly confident bot prediction should pull
	// confidence up to (at least) the ML confidence, exactly like the
	// non-campaign path's blendMLConfidence behavior.
	mlEngine := New(Config{
		Campaign: cfg,
		MLModel: &stubMLModel{result: MLPredictionResult{
			IsBot:      true,
			Confidence: 0.97,
			Category:   BotCategoryDDoS,
		}},
	})
	blended := mlEngine.campaignConfidence(weak)
	if blended < 0.97 {
		t.Fatalf("expected ML bot prediction to raise campaign confidence to at least 0.97, got %.3f", blended)
	}
}

// TestHandleCampaignDetectionUsesBlendedConfidence checks the emitted
// DetectionEvent no longer hardcodes 0.65 and instead reflects the blended
// confidence computed for the campaign.
func TestHandleCampaignDetectionUsesBlendedConfidence(t *testing.T) {
	engine := New(Config{Campaign: testCampaignConfig()})
	detection := baseCampaignDetection()

	engine.handleCampaignDetection(detection)

	event := engine.latestDetections["campaign:"+detection.ID]
	if event == nil {
		t.Fatalf("expected campaign detection to be cached")
	}
	if event.Confidence == 0.65 {
		t.Fatalf("expected campaign detection confidence to be derived from evidence, not hardcoded 0.65")
	}
	if event.Confidence <= 0 || event.Confidence > 1 {
		t.Fatalf("expected confidence in (0,1], got %.3f", event.Confidence)
	}
	if event.WouldBlock {
		t.Fatalf("campaign detections must remain observe-only (WouldBlock=false)")
	}
}

func TestObserveOnlyCampaignDoesNotPenalizeReputation(t *testing.T) {
	rep := reputation.New(time.Hour, 0.9, 100)
	rep.SetIPScoreCap(1000)
	rep.SetASNScoreCap(1000)
	engine := New(Config{
		Campaign:   testCampaignConfig(),
		Reputation: rep,
	})

	detection := baseCampaignDetection()
	ip := detection.SampleIP.String()

	before := rep.GetScore(ip, reputation.TypeIP)
	engine.handleCampaignDetection(detection)
	after := rep.GetScore(ip, reputation.TypeIP)

	if after != before {
		t.Fatalf("observe-only campaign changed sample IP reputation: before=%.3f after=%.3f", before, after)
	}

	if score := rep.GetScore(detection.SampleASN, reputation.TypeASN); score != 0 {
		t.Fatalf("observe-only campaign changed sample ASN reputation: %.3f", score)
	}
}
