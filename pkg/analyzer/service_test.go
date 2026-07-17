package analyzer

import (
	"context"
	"net"
	"testing"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/analyzer/reputation"
	"PacketYeeter/pkg/patterns"
)

// fakeCollectorStream satisfies AnalyzerService_StreamSignalsServer for the
// Send path only; Broadcast delivers asynchronously, so sends are observed
// through a buffered channel.
type fakeCollectorStream struct {
	apiv1.AnalyzerService_StreamSignalsServer
	sent chan *apiv1.Command
}

func newFakeCollectorStream() *fakeCollectorStream {
	return &fakeCollectorStream{sent: make(chan *apiv1.Command, 4)}
}

func (f *fakeCollectorStream) Send(cmd *apiv1.Command) error {
	f.sent <- cmd
	return nil
}

func (f *fakeCollectorStream) waitForCommand(t *testing.T) *apiv1.Command {
	t.Helper()
	select {
	case cmd := <-f.sent:
		return cmd
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for command on collector stream")
		return nil
	}
}

func (f *fakeCollectorStream) expectNoCommand(t *testing.T) {
	t.Helper()
	select {
	case cmd := <-f.sent:
		t.Fatalf("unexpected command delivered to collector stream: %v", cmd)
	case <-time.After(100 * time.Millisecond):
	}
}

func newTestAnalyzer(t *testing.T) *Analyzer {
	t.Helper()
	a, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.cancel)
	rep := reputation.New(time.Hour, 0.95, 100)
	rep.SetIPScoreCap(1000)
	t.Cleanup(rep.Stop)
	a.Reputation = rep
	a.ReputationHelper = NewReputationHelper(rep)
	return a
}

// W2: every stream used to be keyed under the constant "unknown", so a second
// collector's connect overwrote the first and any disconnect evicted the
// still-live sibling.
func TestRegisterCollectorKeysStreamsUniquely(t *testing.T) {
	a := newTestAnalyzer(t)

	csA := &collectorStream{stream: newFakeCollectorStream()}
	csB := &collectorStream{stream: newFakeCollectorStream()}

	// Same (empty) peer context for both: uniqueness must not depend on
	// distinct peer addresses.
	idA := a.registerCollector(context.Background(), csA)
	idB := a.registerCollector(context.Background(), csB)

	if idA == idB {
		t.Fatalf("collector stream ids must be unique, both got %q", idA)
	}

	a.collectorsMu.RLock()
	count := len(a.collectors)
	a.collectorsMu.RUnlock()
	if count != 2 {
		t.Fatalf("expected 2 registered collectors, got %d", count)
	}

	// A's disconnect must not evict B.
	a.unregisterCollector(idA)

	a.collectorsMu.RLock()
	remaining, ok := a.collectors[idB]
	a.collectorsMu.RUnlock()
	if !ok || remaining != csB {
		t.Fatal("unregistering one collector evicted a different live collector stream")
	}
}

// W2: Broadcast must reach every connected collector, not just the last one
// to connect, and the block-command dedup must apply once per broadcast, not
// once per collector.
func TestBroadcastReachesAllCollectors(t *testing.T) {
	a := newTestAnalyzer(t)

	fakeA := newFakeCollectorStream()
	fakeB := newFakeCollectorStream()
	a.registerCollector(context.Background(), &collectorStream{stream: fakeA})
	a.registerCollector(context.Background(), &collectorStream{stream: fakeB})

	a.Broadcast(&apiv1.Command{
		Type:   apiv1.CommandType_COMMAND_BLOCK_IP,
		Ip:     net.ParseIP("192.0.2.10").To4(),
		Reason: "test broadcast",
	})

	fakeA.waitForCommand(t)
	fakeB.waitForCommand(t)

	// The dedup TTL still applies across broadcasts of the same IP.
	a.Broadcast(&apiv1.Command{
		Type:   apiv1.CommandType_COMMAND_BLOCK_IP,
		Ip:     net.ParseIP("192.0.2.10").To4(),
		Reason: "repeat broadcast",
	})
	fakeA.expectNoCommand(t)
	fakeB.expectNoCommand(t)
}

// W3: penalty metadata arrives over an unauthenticated gRPC plane; it must
// never be able to target an arbitrary entity, only the signal's own source.
func TestProcessSignalPenaltyMetadataCannotTargetArbitraryEntity(t *testing.T) {
	a := newTestAnalyzer(t)

	victim := "203.0.113.9"
	attacker := net.ParseIP("198.51.100.7").To4()

	sig := &apiv1.Signal{
		Type:   apiv1.SignalType_SIGNAL_TCP_METADATA,
		Ip:     attacker,
		Weight: 42,
		Metadata: map[string]string{
			"penalty_key":    victim,
			"penalty_type":   "ip",
			"penalty_reason": "spoofed penalty",
		},
	}
	a.processSignal(sig, &collectorStream{stream: newFakeCollectorStream()})

	if score := a.Reputation.GetScore(victim, reputation.TypeIP); score != 0 {
		t.Fatalf("wire metadata penalized an arbitrary third-party entity: victim score = %v, want 0", score)
	}
	if score := a.Reputation.GetScore(net.IP(sig.Ip).String(), reputation.TypeIP); score != 42 {
		t.Fatalf("penalty request must penalize the signal's own source IP: got score %v, want 42", score)
	}
}

// W3 fail-closed: a penalty request with no source IP has nothing legitimate
// to bind to and must be dropped entirely.
func TestProcessSignalPenaltyMetadataWithoutSourceIPIsDropped(t *testing.T) {
	a := newTestAnalyzer(t)

	victim := "203.0.113.9"
	sig := &apiv1.Signal{
		Type:   apiv1.SignalType_SIGNAL_TCP_METADATA,
		Weight: 42,
		Metadata: map[string]string{
			"penalty_key":  victim,
			"penalty_type": "ip",
		},
	}
	a.processSignal(sig, &collectorStream{stream: newFakeCollectorStream()})

	if score := a.Reputation.GetScore(victim, reputation.TypeIP); score != 0 {
		t.Fatalf("sourceless penalty request must be dropped: victim score = %v, want 0", score)
	}
}

// W26: incomplete-handshake signals must feed the pattern tracker's handshake
// counter; it used to be permanently zero because the flag was never set.
func TestProcessSignalRecordsIncompleteHandshakePattern(t *testing.T) {
	a := newTestAnalyzer(t)
	a.PatternTracker = patterns.NewPatternTracker(nil)

	ip := net.ParseIP("192.0.2.55").To4()
	tcpCtx := &apiv1.TCPContext{Ttl: 64, WindowSize: 65535, Mss: 1460}

	a.processSignal(&apiv1.Signal{
		Type:       apiv1.SignalType_SIGNAL_INCOMPLETE_HANDSHAKE,
		Ip:         ip,
		TcpContext: tcpCtx,
	}, &collectorStream{stream: newFakeCollectorStream()})

	pattern := a.PatternTracker.GetPattern(net.IP(ip))
	if pattern == nil {
		t.Fatal("expected a connection pattern to be recorded")
	}
	if pattern.IncompleteHandshakes != 1 {
		t.Fatalf("IncompleteHandshakes = %d, want 1", pattern.IncompleteHandshakes)
	}

	// Other TCP signals must not count as incomplete handshakes.
	a.processSignal(&apiv1.Signal{
		Type:       apiv1.SignalType_SIGNAL_TCP_METADATA,
		Ip:         ip,
		TcpContext: tcpCtx,
	}, &collectorStream{stream: newFakeCollectorStream()})

	pattern = a.PatternTracker.GetPattern(net.IP(ip))
	if pattern.IncompleteHandshakes != 1 {
		t.Fatalf("IncompleteHandshakes = %d after unrelated signal, want still 1", pattern.IncompleteHandshakes)
	}
}
