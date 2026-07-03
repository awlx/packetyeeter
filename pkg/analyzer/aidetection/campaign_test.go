package aidetection

import (
	"fmt"
	"net"
	"strings"
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

// TestCampaignAggregatorSingleScopeDoesNotDoubleCount verifies that when an
// attack only ever touches a single destination subnet and a single
// collector, the per-collector and global aggregate rollups (which internally
// receive a copy of every signal, per campaignKey's fan-out design) do not
// produce their own duplicate detection for the same underlying traffic -
// the aggregates are only distinct rollups when they capture breadth beyond
// their narrower scope.
func TestCampaignAggregatorSingleScopeDoesNotDoubleCount(t *testing.T) {
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

	// Internally, every signal should have fanned out into three campaign
	// buckets: the specific-subnet campaign, the per-collector cross-subnet
	// aggregate, and the fully global aggregate.
	if got := len(agg.campaigns); got != 3 {
		t.Fatalf("expected 3 internal campaign buckets (specific + 2 aggregates), got %d", got)
	}

	detections := agg.Evaluate(now.Add(5 * time.Second))
	if len(detections) != 1 {
		t.Fatalf("expected exactly one detection for a single-subnet/single-collector attack, got %d: %#v", len(detections), detections)
	}
	if detections[0].Reason != "destination_ip_breadth" {
		t.Fatalf("expected destination IP breadth reason, got %q", detections[0].Reason)
	}
	if detections[0].SignalCount != 4 {
		t.Fatalf("expected signal count of 4 (not doubled by the aggregate rollups), got %d", detections[0].SignalCount)
	}
	if detections[0].TotalWeight != 4 {
		t.Fatalf("expected total weight of 4 (not doubled by the aggregate rollups), got %.2f", detections[0].TotalWeight)
	}
}

// TestCampaignAggregatorCombinedSourceAndSubnetSpreadEvasion verifies bug #2:
// an attacker that spreads across many weak source IPs *and* many destination
// subnets, while keeping every individual per-subnet/per-key check below its
// own threshold, is still caught by the weak-source-breadth check evaluated
// independently at the cross-subnet aggregate level.
func TestCampaignAggregatorCombinedSourceAndSubnetSpreadEvasion(t *testing.T) {
	agg := NewCampaignAggregator(testCampaignConfig())
	now := time.Date(2026, 7, 3, 9, 0, 0, 0, time.UTC)

	// Two destination subnets (below MinDestSubnets=3), two events each, each
	// with a distinct weak-weight source IP (four total, meeting
	// MinWeakSourceIPs=4). Each specific-subnet campaign only has 2 events,
	// below MinSignals=4, so it can never independently fire.
	subnetDestIPs := []string{"203.0.113.10", "203.0.114.10"}
	srcIdx := 1
	for _, destIP := range subnetDestIPs {
		for j := 0; j < 2; j++ {
			agg.Record(Signal{
				Type:      SignalIncompleteHandshake,
				Source:    SourceTCP,
				IP:        net.ParseIP(fmt.Sprintf("198.51.100.%d", srcIdx)),
				Weight:    1,
				Timestamp: now.Add(time.Duration(srcIdx) * time.Second),
				Metadata: map[string]interface{}{
					"dest_ip":      destIP,
					"dst_port":     uint32(443),
					"collector_id": "collector-a",
				},
			})
			srcIdx++
		}
	}

	detections := agg.Evaluate(now.Add(5 * time.Second))
	if len(detections) != 1 {
		t.Fatalf("expected exactly one aggregate detection for the combined source+subnet spread, got %d: %#v", len(detections), detections)
	}
	if detections[0].Reason != "weak_source_breadth" {
		t.Fatalf("expected weak source breadth reason from the cross-subnet aggregate, got %q", detections[0].Reason)
	}
	if detections[0].DestSubnets != 2 {
		t.Fatalf("expected 2 destination subnets (below MinDestSubnets, confirming subnet breadth alone did not trigger), got %d", detections[0].DestSubnets)
	}
	if detections[0].SourceIPs != 4 {
		t.Fatalf("expected 4 distinct source IPs, got %d", detections[0].SourceIPs)
	}
}

// TestCampaignAggregatorCollectorSpreadEvasion verifies bug #3: an attacker
// that spreads traffic across multiple collector_id values (while keeping a
// single destination subnet, so no per-collector rollup is individually
// distinct) is still caught via the fully cross-collector global aggregate.
func TestCampaignAggregatorCollectorSpreadEvasion(t *testing.T) {
	agg := NewCampaignAggregator(testCampaignConfig())
	now := time.Date(2026, 7, 3, 9, 0, 0, 0, time.UTC)

	collectors := []string{"collector-a", "collector-b", "collector-c"}
	srcIdx := 1
	for _, collector := range collectors {
		for j := 0; j < 2; j++ {
			agg.Record(Signal{
				Type:      SignalIncompleteHandshake,
				Source:    SourceTCP,
				IP:        net.ParseIP(fmt.Sprintf("198.51.100.%d", srcIdx)),
				Weight:    1,
				Timestamp: now.Add(time.Duration(srcIdx) * time.Second),
				Metadata: map[string]interface{}{
					"dest_ip":      "203.0.113.10",
					"dst_port":     uint32(443),
					"collector_id": collector,
				},
			})
			srcIdx++
		}
	}

	detections := agg.Evaluate(now.Add(5 * time.Second))
	if len(detections) != 1 {
		t.Fatalf("expected exactly one detection from the global cross-collector aggregate, got %d: %#v", len(detections), detections)
	}
	if detections[0].Reason != "weak_source_breadth" {
		t.Fatalf("expected weak source breadth reason from the global aggregate, got %q", detections[0].Reason)
	}
	if detections[0].Collectors != 3 {
		t.Fatalf("expected 3 distinct collectors, got %d", detections[0].Collectors)
	}
	if !strings.Contains(detections[0].Key, "collector=any") {
		t.Fatalf("expected detection to come from the global (collector=any) aggregate key, got %q", detections[0].Key)
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
