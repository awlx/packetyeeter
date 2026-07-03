package aidetection

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestCampaignBaselineWarmupAndAnomalyMultiplier(t *testing.T) {
	tracker := NewCampaignBaselineTracker(CampaignBaselineConfig{
		Tau:               time.Hour,
		MinSamples:        3,
		MinRate:           1,
		AnomalyMultiplier: 3,
		MaxKeys:           16,
	})
	now := time.Date(2026, 7, 3, 9, 0, 0, 0, time.UTC)
	key := CampaignBaselineKey{Protocol: "udp", DstPortBucket: "53", Vector: SignalDNSReflection}

	for i := 0; i < 3; i++ {
		obs := tracker.Observe(key, 2, now.Add(time.Duration(i)*time.Minute))
		if obs.EnoughSamples {
			t.Fatalf("sample %d unexpectedly had enough baseline samples", i)
		}
		if obs.Anomalous {
			t.Fatalf("sample %d unexpectedly marked anomalous during warmup", i)
		}
	}

	obs := tracker.Observe(key, 10, now.Add(3*time.Minute))
	if !obs.EnoughSamples {
		t.Fatalf("expected enough baseline samples after warmup")
	}
	if obs.BaselineRate < 1.9 || obs.BaselineRate > 2.1 {
		t.Fatalf("expected baseline near 2, got %.3f", obs.BaselineRate)
	}
	if obs.Multiplier < 4.9 || obs.Multiplier > 5.1 {
		t.Fatalf("expected 5x multiplier, got %.3f", obs.Multiplier)
	}
	if !obs.Anomalous {
		t.Fatalf("expected high current rate to be marked anomalous")
	}
}

func TestCampaignBaselineUsesMinimumRateGuardrail(t *testing.T) {
	tracker := NewCampaignBaselineTracker(CampaignBaselineConfig{
		Tau:               time.Minute,
		MinSamples:        1,
		MinRate:           5,
		AnomalyMultiplier: 3,
		MaxKeys:           16,
	})
	key := CampaignBaselineKey{Protocol: "tcp", DstPortBucket: "443", Vector: SignalSYNFlood}
	now := time.Date(2026, 7, 3, 9, 0, 0, 0, time.UTC)

	tracker.Observe(key, 0.5, now)
	obs := tracker.Observe(key, 10, now.Add(time.Minute))

	if !obs.EnoughSamples {
		t.Fatalf("expected enough samples after first observation")
	}
	if obs.EffectiveBaseline != 5 {
		t.Fatalf("expected minimum effective baseline of 5, got %.3f", obs.EffectiveBaseline)
	}
	if obs.Multiplier != 2 {
		t.Fatalf("expected multiplier to use minimum baseline guardrail, got %.3f", obs.Multiplier)
	}
	if obs.Anomalous {
		t.Fatalf("minimum baseline guardrail should prevent startup overreaction")
	}
}

func TestCampaignAggregatorAttachesBaselineObservation(t *testing.T) {
	cfg := testCampaignConfig()
	cfg.Baseline = CampaignBaselineConfig{
		Tau:               time.Hour,
		MinSamples:        1,
		MinRate:           0.01,
		AnomalyMultiplier: 3,
		MaxKeys:           16,
	}
	agg := NewCampaignAggregator(cfg)
	now := time.Date(2026, 7, 3, 9, 0, 0, 0, time.UTC)

	recordDNSCampaignSignals(agg, now, 1, 4)
	first := agg.Evaluate(now.Add(5 * time.Second))
	if len(first) != 1 {
		t.Fatalf("expected first campaign detection, got %d", len(first))
	}
	if first[0].Baseline.EnoughSamples {
		t.Fatalf("first detection should be marked as baseline warmup")
	}
	if first[0].Baseline.Protocol != "udp" {
		t.Fatalf("expected udp baseline protocol, got %q", first[0].Baseline.Protocol)
	}
	if first[0].Baseline.DstPortBucket != "53" {
		t.Fatalf("expected DNS port bucket, got %q", first[0].Baseline.DstPortBucket)
	}

	later := now.Add(70 * time.Second)
	recordDNSCampaignSignals(agg, later, 5, 12)
	second := agg.Evaluate(later.Add(5 * time.Second))
	if len(second) != 1 {
		t.Fatalf("expected second campaign detection, got %d", len(second))
	}
	if !second[0].Baseline.EnoughSamples {
		t.Fatalf("second detection should have enough baseline samples")
	}
	if second[0].Baseline.BaselineRate <= 0 {
		t.Fatalf("expected learned baseline rate, got %.3f", second[0].Baseline.BaselineRate)
	}
	if second[0].Baseline.Multiplier <= 1 {
		t.Fatalf("expected elevated multiplier, got %.3f", second[0].Baseline.Multiplier)
	}
}

func TestCampaignDetectionEventIncludesBaselineMetadata(t *testing.T) {
	engine := New(Config{Campaign: testCampaignConfig()})
	detection := CampaignDetection{
		ID:               "campaign-1",
		Key:              "vector=dns_reflection|source=udp|collector=a|dest_subnet=203.0.113.0/24",
		Vector:           SignalDNSReflection,
		Reason:           "destination_ip_breadth",
		FirstSeen:        time.Date(2026, 7, 3, 9, 0, 0, 0, time.UTC),
		LastSeen:         time.Date(2026, 7, 3, 9, 0, 5, 0, time.UTC),
		SignalCount:      8,
		TotalWeight:      8,
		DestinationIPs:   8,
		DestSubnets:      1,
		DestinationPorts: 1,
		SourceIPs:        8,
		SampleIP:         net.ParseIP("198.51.100.10"),
		SampleDestIP:     "203.0.113.10",
		SampleDstPort:    53,
		Baseline: CampaignBaselineObservation{
			ServiceKey:        "protocol=udp|dst_port_bucket=53|vector=dns_reflection",
			Protocol:          "udp",
			DstPortBucket:     "53",
			CurrentRate:       4,
			BaselineRate:      1,
			EffectiveBaseline: 1,
			Multiplier:        4,
			Samples:           5,
			EnoughSamples:     true,
			Anomalous:         true,
		},
	}

	engine.handleCampaignDetection(detection)
	event := engine.latestDetections["campaign:campaign-1"]
	if event == nil {
		t.Fatalf("expected campaign detection to be cached")
	}
	if event.WouldBlock {
		t.Fatalf("campaign baseline metadata must not change observe-only behavior")
	}
	if got := event.Metadata["baseline_multiplier"]; got != 4.0 {
		t.Fatalf("expected baseline multiplier metadata, got %#v", got)
	}
	if got := event.Metadata["baseline_enough_samples"]; got != true {
		t.Fatalf("expected enough-samples metadata, got %#v", got)
	}
	if got := event.Metadata["baseline_anomalous"]; got != true {
		t.Fatalf("expected anomalous metadata, got %#v", got)
	}
}

func recordDNSCampaignSignals(agg *CampaignAggregator, start time.Time, firstIP, lastIP int) {
	for i := firstIP; i <= lastIP; i++ {
		agg.Record(Signal{
			Type:      SignalUDPFlood,
			Source:    SourceUDP,
			IP:        net.ParseIP(fmt.Sprintf("198.51.100.%d", i)),
			Weight:    1,
			Timestamp: start.Add(time.Duration(i-firstIP+1) * time.Second),
			Metadata: map[string]interface{}{
				"dest_ip":      fmt.Sprintf("203.0.113.%d", i),
				"dst_port":     uint32(53),
				"collector_id": "collector-a",
			},
		})
	}
}
