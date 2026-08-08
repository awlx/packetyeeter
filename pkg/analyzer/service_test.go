package analyzer

import (
	"context"
	"math"
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

// #74.1: Broadcasting a block with zero connected collectors must NOT reserve
// the dedup slot, so a collector connecting afterward still receives the block.
func TestBroadcastWithNoCollectorsDoesNotReserveDedup(t *testing.T) {
	a := newTestAnalyzer(t)

	ip := net.ParseIP("192.0.2.55").To4()
	// No collectors connected yet.
	a.Broadcast(&apiv1.Command{Type: apiv1.CommandType_COMMAND_BLOCK_IP, Ip: ip, Reason: "no recipients"})

	// The IP must not have been marked as recently blocked.
	if a.wasRecentlyBlocked(net.IP(ip)) {
		t.Fatal("broadcast with no collectors reserved the dedup slot; a reconnecting collector would miss the block")
	}

	// Now a collector connects and the same block is re-issued: it must be
	// delivered (not suppressed as a duplicate).
	fake := newFakeCollectorStream()
	a.registerCollector(context.Background(), &collectorStream{stream: fake})
	a.Broadcast(&apiv1.Command{Type: apiv1.CommandType_COMMAND_BLOCK_IP, Ip: ip, Reason: "after reconnect"})
	fake.waitForCommand(t)
}

// #74.3: collector admission is bounded so an unauthenticated peer cannot grow
// the collectors map without limit.
func TestRegisterCollectorEnforcesMaxCollectors(t *testing.T) {
	a := newTestAnalyzer(t)
	a.Config.MaxCollectors = 2

	id1 := a.registerCollector(context.Background(), &collectorStream{stream: newFakeCollectorStream()})
	id2 := a.registerCollector(context.Background(), &collectorStream{stream: newFakeCollectorStream()})
	id3 := a.registerCollector(context.Background(), &collectorStream{stream: newFakeCollectorStream()})

	if id1 == "" || id2 == "" {
		t.Fatalf("first two collectors should be admitted, got %q and %q", id1, id2)
	}
	if id3 != "" {
		t.Fatalf("third collector should be refused past the cap, got id %q", id3)
	}

	a.collectorsMu.RLock()
	count := len(a.collectors)
	a.collectorsMu.RUnlock()
	if count != 2 {
		t.Fatalf("collectors map should be capped at 2, got %d", count)
	}

	// Freeing a slot lets a new collector in.
	a.unregisterCollector(id1)
	id4 := a.registerCollector(context.Background(), &collectorStream{stream: newFakeCollectorStream()})
	if id4 == "" {
		t.Fatal("a collector should be admitted after a slot is freed")
	}
}

// The penalty_key/penalty_type/penalty_reason wire metadata is fully disabled:
// it arrives over an unauthenticated gRPC plane with an attacker-controlled
// source IP, so it must never penalize anyone - neither an arbitrary victim nor
// the signal's own (spoofable) source. Reputation is driven only by signals the
// analyzer actually scores.
func TestProcessSignalPenaltyMetadataIsIgnored(t *testing.T) {
	a := newTestAnalyzer(t)

	victim := "203.0.113.9"
	source := net.ParseIP("198.51.100.7").To4()

	sig := &apiv1.Signal{
		Type:   apiv1.SignalType_SIGNAL_TCP_METADATA,
		Ip:     source,
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
	if score := a.Reputation.GetScore(net.IP(sig.Ip).String(), reputation.TypeIP); score != 0 {
		t.Fatalf("wire penalty metadata must not penalize even the (spoofable) source IP: got score %v, want 0", score)
	}
}

// A penalty request with a non-finite weight must never corrupt reputation.
// (The whole metadata path is disabled, so this is a belt-and-suspenders guard.)
func TestProcessSignalPenaltyMetadataWithBadWeightIsIgnored(t *testing.T) {
	a := newTestAnalyzer(t)

	source := net.ParseIP("198.51.100.8").To4()
	sig := &apiv1.Signal{
		Type:   apiv1.SignalType_SIGNAL_TCP_METADATA,
		Ip:     source,
		Weight: math.Inf(1),
		Metadata: map[string]string{
			"penalty_key":  net.IP(source).String(),
			"penalty_type": "ip",
		},
	}
	a.processSignal(sig, &collectorStream{stream: newFakeCollectorStream()})

	if score := a.Reputation.GetScore(net.IP(source).String(), reputation.TypeIP); score != 0 || math.IsInf(score, 0) || math.IsNaN(score) {
		t.Fatalf("non-finite penalty weight must not reach reputation: got %v", score)
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
