package aidetection

import (
	"net"
	"testing"
	"time"
)

func TestHotShardQueueDrainsWithoutEvidenceLoss(t *testing.T) {
	const signalCount = 10000

	engine := New(Config{
		Workers:      16,
		BufferSize:   10000,
		WarmupPeriod: time.Nanosecond,
	})
	engine.Start()
	defer engine.Stop()

	ip := net.ParseIP("192.0.2.1")
	deadline := time.Now().Add(30 * time.Second)
	for emitted := 0; emitted < signalCount; {
		batch := min(500, signalCount-emitted)
		for range batch {
			engine.EmitSignal(Signal{
				Type:      SignalIncompleteHandshake,
				Source:    SourceTCP,
				IP:        ip,
				ASN:       "AS64500",
				Org:       "stress",
				Weight:    1,
				Timestamp: time.Now(),
				Metadata: map[string]interface{}{
					"dest_ip":      "198.51.100.1",
					"dst_port":     uint32(443),
					"collector_id": "stress",
				},
			})
		}
		emitted += batch

		for {
			engine.metricsMu.Lock()
			processed := engine.signalsByIP[ip.String()]
			engine.metricsMu.Unlock()
			if processed == uint64(emitted) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("hot shard did not drain: queue depth=%d processed=%d/%d", engine.totalQueueDepth(), processed, emitted)
			}
			time.Sleep(time.Millisecond)
		}
	}

	if depth := engine.totalQueueDepth(); depth != 0 {
		t.Fatalf("expected drained queues, depth=%d", depth)
	}
}

func BenchmarkProcessSignalHotKey(b *testing.B) {
	const signalsPerBatch = 5000

	for range b.N {
		engine := New(Config{
			Workers:      1,
			BufferSize:   signalsPerBatch,
			WarmupPeriod: time.Hour,
		})
		windowSignals := make(map[string][]Signal)
		windowSummaries := make(map[string]*signalWindowSummary)
		signal := Signal{
			Type:      SignalIncompleteHandshake,
			Source:    SourceTCP,
			IP:        net.ParseIP("192.0.2.1"),
			ASN:       "AS64500",
			Org:       "benchmark",
			Weight:    1,
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"dest_ip":      "198.51.100.1",
				"dst_port":     uint32(443),
				"collector_id": "benchmark",
			},
		}

		b.StartTimer()
		for range signalsPerBatch {
			engine.processSignal(signal, windowSignals, windowSummaries)
		}
		b.StopTimer()
	}

	b.ReportMetric(float64(signalsPerBatch), "signals/op")
}
