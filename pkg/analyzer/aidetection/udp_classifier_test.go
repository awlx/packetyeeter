package aidetection

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestClassifyUDPAttackVectorByPort(t *testing.T) {
	tests := []struct {
		name string
		port uint32
		want SignalType
	}{
		{name: "dns", port: 53, want: SignalDNSReflection},
		{name: "ntp", port: 123, want: SignalNTPReflection},
		{name: "ssdp", port: 1900, want: SignalSSDPReflection},
		{name: "cldap", port: 389, want: SignalCLDAPReflection},
		{name: "memcached", port: 11211, want: SignalMemcachedReflection},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyUDPAttackVector(Signal{
				Type:   SignalUDPFlood,
				Source: SourceUDP,
				Metadata: map[string]interface{}{
					"dst_port": tt.port,
				},
			})
			if got != tt.want {
				t.Fatalf("expected %s, got %s", tt.want, got)
			}
		})
	}
}

func TestClassifyUDPAttackVectorMetadataHints(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]interface{}
		want     SignalType
	}{
		{name: "dns metadata", metadata: map[string]interface{}{"dns_qtype": "ANY"}, want: SignalDNSReflection},
		{name: "ssdp payload", metadata: map[string]interface{}{"payload_sample": "M-SEARCH * HTTP/1.1"}, want: SignalSSDPReflection},
		{name: "quic initial", metadata: map[string]interface{}{"dst_port": uint32(443), "quic_packet_type": "initial", "quic_version": "1"}, want: SignalQUICInitialFlood},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyUDPAttackVector(Signal{Type: SignalUDPFlood, Source: SourceUDP, Metadata: tt.metadata})
			if got != tt.want {
				t.Fatalf("expected %s, got %s", tt.want, got)
			}
		})
	}
}

func TestClassifyUDPAttackVectorFallbackAndGuards(t *testing.T) {
	if got := classifyUDPAttackVector(Signal{Type: SignalUDPFlood, Source: SourceUDP}); got != SignalUDPFlood {
		t.Fatalf("expected ambiguous UDP signal to stay udp_flood, got %s", got)
	}
	if got := classifyUDPAttackVector(Signal{Type: SignalUDPFlood, Source: SourceUDP, Metadata: map[string]interface{}{"dst_port": uint32(443)}}); got != SignalUDPFlood {
		t.Fatalf("expected UDP/443 without QUIC metadata to stay udp_flood, got %s", got)
	}
	if got := classifyUDPAttackVector(Signal{Type: SignalSYNFlood, Source: SourceTCP, Metadata: map[string]interface{}{"dst_port": uint32(53)}}); got != SignalSYNFlood {
		t.Fatalf("expected non-UDP signal to keep original vector, got %s", got)
	}
	if got := classifyUDPAttackVector(Signal{Type: SignalUDPFlood, Source: SourceUDP, Metadata: map[string]interface{}{"dst_port": uint32(53), "transport": "tcp"}}); got != SignalUDPFlood {
		t.Fatalf("expected conflicting TCP transport metadata to avoid DNS classification, got %s", got)
	}
	if got := classifyUDPAttackVector(Signal{Type: SignalUDPFlood, Source: SourceUDP, Metadata: map[string]interface{}{"dst_port": uint32(53), "protocol": "tcp"}}); got != SignalUDPFlood {
		t.Fatalf("expected conflicting TCP protocol metadata to avoid DNS classification, got %s", got)
	}
}

func TestCampaignAggregatorUsesUDPReflectionVector(t *testing.T) {
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
				"dst_port":     uint32(53),
				"collector_id": "collector-a",
			},
		})
	}

	detections := agg.Evaluate(now.Add(5 * time.Second))
	if len(detections) != 1 {
		t.Fatalf("expected one campaign detection, got %d: %#v", len(detections), detections)
	}
	if detections[0].Vector != SignalDNSReflection {
		t.Fatalf("expected DNS reflection vector, got %s", detections[0].Vector)
	}
	if detections[0].Reason != "destination_ip_breadth" {
		t.Fatalf("expected destination IP breadth reason, got %q", detections[0].Reason)
	}
}
