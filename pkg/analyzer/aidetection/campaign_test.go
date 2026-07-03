package aidetection

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func testCampaignConfig() CampaignConfig {
	return CampaignConfig{
		Window:              time.Minute,
		Retention:           2 * time.Minute,
		MinSignals:          4,
		MinDestIPs:          4,
		MinDestSubnets:      3,
		MinDestPorts:        4,
		MinWeakSourceIPs:    4,
		WeakSourceMaxWeight: 2,
		WeakSignalMaxWeight: 1.5,
	}
}

func TestCampaignAggregatorGroupsDestinationBreadth(t *testing.T) {
	agg := NewCampaignAggregator(testCampaignConfig())
	now := time.Date(2026, 7, 3, 9, 0, 0, 0, time.UTC)

	for i := 1; i <= 4; i++ {
		agg.Record(Signal{
			Type:      SignalUDPFlood,
			Source:    SourceUDP,
			IP:        net.ParseIP(fmt.Sprintf("198.51.100.%d", i)),
			Weight:    1,
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Metadata: map[string]interface{}{
				"dest_ip":      fmt.Sprintf("203.0.113.%d", i),
				"dst_port":     uint32(443),
				"collector_id": "collector-a",
			},
		})
	}

	detections := agg.Evaluate(now.Add(5 * time.Second))
	if len(detections) != 1 {
		t.Fatalf("expected one campaign detection, got %d: %#v", len(detections), detections)
	}
	if detections[0].Reason != "destination_ip_breadth" {
		t.Fatalf("expected destination IP breadth reason, got %q", detections[0].Reason)
	}
	if detections[0].DestinationIPs != 4 {
		t.Fatalf("expected 4 destination IPs, got %d", detections[0].DestinationIPs)
	}
}

func TestCampaignAggregatorDetectsCrossSubnetBreadth(t *testing.T) {
	agg := NewCampaignAggregator(testCampaignConfig())
	now := time.Date(2026, 7, 3, 9, 0, 0, 0, time.UTC)

	for i := 0; i < 4; i++ {
		agg.Record(Signal{
			Type:      SignalSYNFlood,
			Source:    SourceTCP,
			IP:        net.ParseIP(fmt.Sprintf("198.51.100.%d", i+1)),
			Weight:    1,
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Metadata: map[string]interface{}{
				"dest_ip":      fmt.Sprintf("203.0.%d.10", i),
				"dst_port":     uint32(80),
				"collector_id": "collector-a",
			},
		})
	}

	detections := agg.Evaluate(now.Add(5 * time.Second))
	if len(detections) != 1 {
		t.Fatalf("expected one aggregate campaign detection, got %d", len(detections))
	}
	if detections[0].Reason != "destination_subnet_breadth" {
		t.Fatalf("expected destination subnet breadth reason, got %q", detections[0].Reason)
	}
	if detections[0].DestSubnets != 4 {
		t.Fatalf("expected 4 destination subnets, got %d", detections[0].DestSubnets)
	}
}

func TestCampaignAggregatorExpiresOldSignals(t *testing.T) {
	agg := NewCampaignAggregator(testCampaignConfig())
	now := time.Date(2026, 7, 3, 9, 0, 0, 0, time.UTC)

	for i := 1; i <= 4; i++ {
		agg.Record(Signal{
			Type:      SignalUDPFlood,
			Source:    SourceUDP,
			IP:        net.ParseIP(fmt.Sprintf("198.51.100.%d", i)),
			Weight:    1,
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Metadata: map[string]interface{}{
				"dest_ip": fmt.Sprintf("203.0.113.%d", i),
			},
		})
	}

	detections := agg.Evaluate(now.Add(2 * time.Minute))
	if len(detections) != 0 {
		t.Fatalf("expected no detection after window expiry, got %d", len(detections))
	}
	if active := agg.ActiveCampaigns(now.Add(3 * time.Minute)); active != 0 {
		t.Fatalf("expected expired campaigns to be removed, got %d active", active)
	}
}

func TestCampaignAggregatorWeakSourceBreadthGuard(t *testing.T) {
	agg := NewCampaignAggregator(testCampaignConfig())
	now := time.Date(2026, 7, 3, 9, 0, 0, 0, time.UTC)

	for i := 1; i <= 4; i++ {
		agg.Record(Signal{
			Type:      SignalIncompleteHandshake,
			Source:    SourceTCP,
			IP:        net.ParseIP(fmt.Sprintf("198.51.100.%d", i)),
			Weight:    1,
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Metadata: map[string]interface{}{
				"dest_ip":  "203.0.113.10",
				"dst_port": uint32(443),
			},
		})
	}

	detections := agg.Evaluate(now.Add(5 * time.Second))
	if len(detections) != 1 {
		t.Fatalf("expected weak source breadth detection, got %d", len(detections))
	}
	if detections[0].Reason != "weak_source_breadth" {
		t.Fatalf("expected weak source breadth reason, got %q", detections[0].Reason)
	}

	agg = NewCampaignAggregator(testCampaignConfig())
	for i := 1; i <= 4; i++ {
		agg.Record(Signal{
			Type:      SignalIncompleteHandshake,
			Source:    SourceTCP,
			IP:        net.ParseIP(fmt.Sprintf("198.51.100.%d", i)),
			Weight:    3,
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Metadata: map[string]interface{}{
				"dest_ip":  "203.0.113.10",
				"dst_port": uint32(443),
			},
		})
	}
	if detections := agg.Evaluate(now.Add(5 * time.Second)); len(detections) != 0 {
		t.Fatalf("expected strong per-source weights to be guarded, got %d detections", len(detections))
	}
}
