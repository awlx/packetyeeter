package aidetection

import (
	"net"
	"testing"
	"time"
)

func BenchmarkCampaignRecordAtCap(b *testing.B) {
	agg := NewCampaignAggregator(CampaignConfig{})
	now := time.Now()
	signalAt := func(i int) Signal {
		return Signal{
			Type:      SignalUDPFlood,
			Source:    SourceUDP,
			IP:        net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)),
			ASN:       "AS64500",
			Org:       "benchmark",
			Weight:    1,
			Timestamp: now,
			Metadata: map[string]interface{}{
				"dest_ip":      "198.51.100.1",
				"dst_port":     uint32(53),
				"collector_id": "benchmark",
			},
		}
	}
	for i := range 2 * DefaultCampaignConfig().MaxEvents {
		agg.Record(signalAt(i))
	}
	signals := make([]Signal, 1<<16)
	for i := range signals {
		signals[i] = signalAt(i + 1<<20)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		agg.Record(signals[i&(len(signals)-1)])
	}
}
