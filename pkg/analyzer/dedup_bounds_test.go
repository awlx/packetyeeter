package analyzer

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/metrics"
)

// registerDiscard registers n collectors whose sends go nowhere.
func registerDiscard(t *testing.T, a *Analyzer, n int) []*collectorStream {
	t.Helper()
	out := make([]*collectorStream, n)
	for i := range out {
		out[i] = &collectorStream{stream: discardStream{}}
		if a.registerCollector(context.Background(), out[i]) == "" {
			t.Fatal("collector not admitted")
		}
	}
	return out
}

func sentEntries(a *Analyzer, ip net.IP) int {
	a.recentBlocksMu.Lock()
	defer a.recentBlocksMu.Unlock()
	if r, ok := a.recentBlocks[ip.String()]; ok {
		return len(r.sent)
	}
	return 0
}

// reservedFor reports whether ip's reservation holds a sent entry for cs.
func reservedFor(a *Analyzer, ip net.IP, cs *collectorStream) bool {
	a.recentBlocksMu.Lock()
	defer a.recentBlocksMu.Unlock()
	r, ok := a.recentBlocks[ip.String()]
	if !ok {
		return false
	}
	_, got := r.sent[cs.dedupKey()]
	return got
}

func concat(parts ...[]*collectorStream) []*collectorStream {
	var out []*collectorStream
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// A Broadcast to many collectors keeps one mark, not an entry per
// collector, and a repeat within the TTL reaches only collectors that
// connected since.
func TestWideBroadcastDedupIsBounded(t *testing.T) {
	a := newTestAnalyzer(t)
	ip := net.ParseIP("198.51.100.10")
	old := registerDiscard(t, a, 200)
	t0 := time.Now()

	fresh, publish := a.reserveBlock(ip, scopeBroadcast, old, t0)
	if len(fresh) != len(old) || !publish {
		t.Fatalf("first broadcast: fresh = %d publish = %v, want %d true", len(fresh), publish, len(old))
	}
	if n := sentEntries(a, ip); n != 0 {
		t.Fatalf("sent entries = %d, want 0 (one broadcast mark)", n)
	}

	late := registerDiscard(t, a, 3)
	fresh, _ = a.reserveBlock(ip, scopeBroadcast, concat(old, late), t0.Add(10*time.Second))
	if len(fresh) != len(late) {
		t.Fatalf("repeat broadcast reached %d collectors, want the %d that connected since", len(fresh), len(late))
	}
	for i, f := range fresh {
		if f != late[i] {
			t.Fatalf("repeat broadcast reached a collector that already had the block")
		}
	}
	if n := sentEntries(a, ip); n != len(late) {
		t.Fatalf("sent entries = %d, want %d", n, len(late))
	}

	// A collector the mark covers is not sent its own block again; a later
	// one is, and the mark expires a TTL after it was set.
	if fresh, _ := a.reserveBlock(ip, scopeLocal, old[:1], t0.Add(20*time.Second)); len(fresh) != 0 {
		t.Fatal("local block re-sent to a collector the broadcast reached")
	}
	if fresh, _ := a.reserveBlock(ip, scopeLocal, old[:1], t0.Add(recentBlockTTL)); len(fresh) != 1 {
		t.Fatal("broadcast mark outlived the TTL")
	}
}

// With the scrub evidence gate, the excluded scrub nodes are not covered by
// the mark, so a repeat Broadcast once they are eligible reaches them.
func TestWideBroadcastSkipsGatedScrubNodes(t *testing.T) {
	a := newTestAnalyzer(t)
	ip := net.ParseIP("198.51.100.11")
	hosts := registerDiscard(t, a, 100)
	scrub := registerDiscard(t, a, 2)
	more := registerDiscard(t, a, 100)
	t0 := time.Now()

	if fresh, _ := a.reserveBlockExcept(ip, scopeBroadcast, concat(hosts, more), scrub, t0); len(fresh) != 200 {
		t.Fatalf("gated broadcast reached %d, want 200", len(fresh))
	}
	fresh, _ := a.reserveBlockExcept(ip, scopeBroadcast, concat(hosts, scrub, more), nil, t0.Add(time.Second))
	if len(fresh) != 2 || fresh[0] != scrub[0] || fresh[1] != scrub[1] {
		t.Fatalf("repeat broadcast reached %d collectors, want the 2 newly eligible scrub nodes", len(fresh))
	}
}

// A collector that got its own block before a wide Broadcast is skipped by
// it and by its mark, so its dedup still ends a TTL after its own block,
// not after the Broadcast.
func TestWideBroadcastKeepsEarlierPerCollectorExpiry(t *testing.T) {
	a := newTestAnalyzer(t)
	ip := net.ParseIP("198.51.100.12")
	all := registerDiscard(t, a, 100)
	t0 := time.Now()

	a.reserveBlock(ip, scopeLocal, all[50:51], t0)
	if fresh, _ := a.reserveBlock(ip, scopeBroadcast, all, t0.Add(30*time.Second)); len(fresh) != 99 {
		t.Fatalf("broadcast reached %d, want 99", len(fresh))
	}
	if fresh, _ := a.reserveBlock(ip, scopeLocal, all[50:51], t0.Add(recentBlockTTL+time.Second)); len(fresh) != 1 {
		t.Fatal("local block suppressed past its TTL by a later broadcast")
	}
}

// When a repeat Broadcast would add more entries than the bound, it starts
// a new mark and re-sends to everyone, so the per-source state stays
// bounded and no collector is suppressed for over a TTL after its last send.
func TestWideBroadcastOverflowRestartsMark(t *testing.T) {
	a := newTestAnalyzer(t)
	ip := net.ParseIP("198.51.100.13")
	old := registerDiscard(t, a, 100)
	t0 := time.Now()
	a.reserveBlock(ip, scopeBroadcast, old, t0)

	late := registerDiscard(t, a, maxBlockSentEntries+1)
	all := concat(old, late)
	fresh, _ := a.reserveBlock(ip, scopeBroadcast, all, t0.Add(30*time.Second))
	if len(fresh) != len(all) {
		t.Fatalf("overflowing broadcast reached %d, want all %d", len(fresh), len(all))
	}
	if n := sentEntries(a, ip); n != 0 {
		t.Fatalf("sent entries = %d, want 0", n)
	}
	if fresh, _ := a.reserveBlock(ip, scopeBroadcast, all, t0.Add(65*time.Second)); len(fresh) != 0 {
		t.Fatalf("broadcast 35s after the last one reached %d collectors", len(fresh))
	}
	if fresh, _ := a.reserveBlock(ip, scopeBroadcast, all, t0.Add(90*time.Second)); len(fresh) != len(all) {
		t.Fatalf("broadcast a TTL after the last one reached %d, want %d", len(fresh), len(all))
	}
}

// End to end: a Broadcast to many connected collectors reaches each once
// and keeps no per-collector entries.
func TestBroadcastManyCollectorsSendsOnce(t *testing.T) {
	a := newTestAnalyzer(t)
	var sends atomic.Int64
	for range 150 {
		cs := &collectorStream{stream: countingStream{n: &sends}}
		if a.registerCollector(context.Background(), cs) == "" {
			t.Fatal("collector not admitted")
		}
	}
	a.Broadcast(blockCmd("198.51.100.14"))
	waitFor(t, "broadcast sends", func() bool { return sends.Load() == 150 })
	a.Broadcast(blockCmd("198.51.100.14"))
	time.Sleep(50 * time.Millisecond)
	if n := sends.Load(); n != 150 {
		t.Fatalf("sends = %d after a repeat broadcast, want 150", n)
	}
	if n := sentEntries(a, net.ParseIP("198.51.100.14")); n != 0 {
		t.Fatalf("sent entries = %d, want 0", n)
	}
}

type countingStream struct {
	apiv1.AnalyzerService_StreamSignalsServer
	n *atomic.Int64
}

func (s countingStream) Send(*apiv1.Command) error {
	s.n.Add(1)
	return nil
}

// recordingGate holds every Send until gate closes, then records it; with
// fail set, Sends of a block fail instead.
type recordingGate struct {
	apiv1.AnalyzerService_StreamSignalsServer
	entered chan struct{}
	gate    chan struct{}
	sent    chan *apiv1.Command
	fail    atomic.Bool
}

func newRecordingGate() *recordingGate {
	return &recordingGate{entered: make(chan struct{}, 1), gate: make(chan struct{}), sent: make(chan *apiv1.Command, 2*scrubFanoutQueueSize)}
}

func (s *recordingGate) Send(cmd *apiv1.Command) error {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	<-s.gate
	if s.fail.Load() && cmd.GetType() == apiv1.CommandType_COMMAND_BLOCK_IP {
		return errors.New("send failed")
	}
	s.sent <- cmd
	return nil
}

// waitEntered waits until a Send has started.
func (s *recordingGate) waitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-s.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a send to start")
	}
}

// waitForBlock waits for a block of ip on s, skipping other commands.
func (s *recordingGate) waitForBlock(t *testing.T, ip string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case cmd := <-s.sent:
			if cmd.GetType() == apiv1.CommandType_COMMAND_BLOCK_IP && net.IP(cmd.GetIp()).Equal(net.ParseIP(ip)) {
				return
			}
		case <-deadline:
			t.Fatalf("peer never got the block of %s", ip)
		}
	}
}

func registerGatedPeer(t *testing.T, a *Analyzer) (*collectorStream, *recordingGate) {
	t.Helper()
	s := newRecordingGate()
	return registerStream(t, a, "scrub", trustedScrubName, s), s
}

// A fan-out block dropped because the peer's queue was full does not keep
// the peer reserved: the next trusted trip within the TTL delivers it.
func TestFanoutQueueFullReleasesReservation(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})
	allowScrubNames(a)
	fakeOrigin := newBufferedFake(2 * scrubFanoutQueueSize)
	origin := registerStream(t, a, "scrub", trustedScrubName, fakeOrigin)
	peerCS, peer := registerGatedPeer(t, a)

	a.sendCommand(origin, unblockCmd("192.0.2.200"), true)
	peer.waitEntered(t) // the worker holds this one; the queue is empty
	for range scrubFanoutQueueSize {
		a.sendCommand(origin, unblockCmd("192.0.2.200"), true)
	}
	before := testutil.ToFloat64(metrics.ScrubCommandFanoutDropped.WithLabelValues("queue_full"))
	a.sendCommand(origin, blockCmd("192.0.2.201"), true)
	for len(fakeOrigin.sent) > 0 {
		fakeOrigin.waitForCommand(t)
	}
	if got := testutil.ToFloat64(metrics.ScrubCommandFanoutDropped.WithLabelValues("queue_full")) - before; got != 1 {
		t.Fatalf("queue_full delta = %v, want 1", got)
	}
	if reservedFor(a, net.ParseIP("192.0.2.201"), peerCS) {
		t.Fatal("dropped fan-out still reserved for the peer")
	}

	close(peer.gate)
	waitFor(t, "peer queue drained", func() bool { return len(peerCS.fanout) == 0 })
	a.sendCommand(origin, blockCmd("192.0.2.201"), true)
	fakeOrigin.expectNoCommand(t)
	peer.waitForBlock(t, "192.0.2.201")
}

// A queued fan-out dropped because the peer stopped being a trusted scrub
// stream is released, so the peer gets the block once it is one again.
func TestFanoutRoleChangedReleasesReservation(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})
	allowScrubNames(a)
	origin, _ := registerTrusted(t, a, "scrub")
	peerCS, peer := registerGatedPeer(t, a)

	a.sendCommand(origin, unblockCmd("192.0.2.210"), true)
	peer.waitEntered(t)
	a.sendCommand(origin, blockCmd("192.0.2.211"), true)
	before := testutil.ToFloat64(metrics.ScrubCommandFanoutDropped.WithLabelValues("role_changed"))
	peerCS.setRole("host")
	close(peer.gate)
	waitFor(t, "role_changed drop", func() bool {
		return testutil.ToFloat64(metrics.ScrubCommandFanoutDropped.WithLabelValues("role_changed"))-before == 1
	})
	waitFor(t, "reservation released", func() bool { return !reservedFor(a, net.ParseIP("192.0.2.211"), peerCS) })

	peerCS.setRole("scrub")
	a.sendCommand(origin, blockCmd("192.0.2.211"), true)
	peer.waitForBlock(t, "192.0.2.211")
}

// A fan-out whose send failed is released too.
func TestFanoutSendErrorReleasesReservation(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})
	allowScrubNames(a)
	origin, _ := registerTrusted(t, a, "scrub")
	peerCS, peer := registerGatedPeer(t, a)
	peer.fail.Store(true)
	close(peer.gate)

	a.sendCommand(origin, blockCmd("192.0.2.221"), true)
	peer.waitEntered(t)
	waitFor(t, "reservation released", func() bool { return !reservedFor(a, net.ParseIP("192.0.2.221"), peerCS) })

	peer.fail.Store(false)
	a.sendCommand(origin, blockCmd("192.0.2.221"), true)
	peer.waitForBlock(t, "192.0.2.221")
}

// Release is compare-and-delete: it keeps a reservation made since.
func TestReleaseBlockKeepsNewerReservation(t *testing.T) {
	a := newTestAnalyzer(t)
	cs := registerDiscard(t, a, 1)[0]
	cmd := blockCmd("192.0.2.230")
	ip := net.ParseIP("192.0.2.230")
	t0 := time.Now()
	a.reserveBlock(ip, scopeFanout, []*collectorStream{cs}, t0)
	a.releaseBlock(cs, cmd, t0)
	a.reserveBlock(ip, scopeFanout, []*collectorStream{cs}, t0.Add(time.Second))
	a.releaseBlock(cs, cmd, t0)
	if !reservedFor(a, ip, cs) {
		t.Fatal("stale release removed a newer reservation")
	}
}

// Registration renumbers a stream, so one that got a dedup key before it
// connected is still not covered by a Broadcast sent before it connected.
func TestWideBroadcastMissesStreamKeyedBeforeRegistration(t *testing.T) {
	a := newTestAnalyzer(t)
	ip := net.ParseIP("198.51.100.15")
	early := &collectorStream{stream: discardStream{}}
	early.dedupKey()
	old := registerDiscard(t, a, 100)
	t0 := time.Now()
	a.reserveBlock(ip, scopeBroadcast, old, t0)
	if a.registerCollector(context.Background(), early) == "" {
		t.Fatal("collector not admitted")
	}
	fresh, _ := a.reserveBlock(ip, scopeBroadcast, append(old, early), t0.Add(time.Second))
	if len(fresh) != 1 || fresh[0] != early {
		t.Fatalf("repeat broadcast reached %d collectors, want only the one that connected since", len(fresh))
	}
}

// Local and fan-out entries do not count toward the Broadcast bound: with
// many collectors already blocked locally, each repeat Broadcast that finds
// one newcomer sends only to it, and every collector gets the block once.
func TestRepeatBroadcastIgnoresLocalEntriesForBound(t *testing.T) {
	a := newTestAnalyzer(t)
	ip := net.ParseIP("198.51.100.16")
	all := registerDiscard(t, a, 500)
	t0 := time.Now()
	got := make(map[*collectorStream]int)
	for i := range maxBlockSentEntries {
		for _, f := range a.reserveBlockForTest(ip, scopeLocal, all[i:i+1], t0) {
			got[f]++
		}
	}
	for _, f := range a.reserveBlockForTest(ip, scopeFanout, all[64:66], t0) {
		got[f]++
	}
	fresh := a.reserveBlockForTest(ip, scopeBroadcast, all, t0.Add(time.Second))
	if len(fresh) != 500-66 {
		t.Fatalf("first broadcast reached %d, want %d", len(fresh), 500-66)
	}
	for _, f := range fresh {
		got[f]++
	}
	for i := range 2 * maxBlockSentEntries {
		all = append(all, registerDiscard(t, a, 1)...)
		fresh := a.reserveBlockForTest(ip, scopeBroadcast, all, t0.Add(time.Duration(2+i)*100*time.Millisecond))
		if len(fresh) != 1 || fresh[0] != all[len(all)-1] {
			if i < maxBlockSentEntries {
				t.Fatalf("repeat %d reached %d collectors, want only the newcomer", i, len(fresh))
			}
			// Past the bound everyone is sent again; stop counting there.
			break
		}
		got[fresh[0]]++
		if i == maxBlockSentEntries-1 {
			for _, cs := range all {
				if got[cs] != 1 {
					t.Fatalf("collector got the block %d times, want 1", got[cs])
				}
			}
		}
	}
}

// Crossing the bound while a mark is live: newcomers within the bound get
// only their own send and keep the mark's time; the one past it starts a
// new mark sent to everyone, after which repeats send nothing.
func TestBroadcastBoundCrossedWithLiveMark(t *testing.T) {
	a := newTestAnalyzer(t)
	ip := net.ParseIP("198.51.100.17")
	all := registerDiscard(t, a, 100)
	t0 := time.Now()
	a.reserveBlock(ip, scopeBroadcast, all, t0)
	for i := range maxBlockSentEntries {
		all = append(all, registerDiscard(t, a, 1)...)
		if fresh, _ := a.reserveBlock(ip, scopeBroadcast, all, t0.Add(time.Duration(i+1)*100*time.Millisecond)); len(fresh) != 1 {
			t.Fatalf("newcomer %d: broadcast reached %d, want 1", i, len(fresh))
		}
	}
	// The mark keeps its time: its collectors are due again a TTL after t0.
	a.recentBlocksMu.Lock()
	markAt, entries := a.recentBlocks[ip.String()].bcast.at, a.recentBlocks[ip.String()].bcastEntries
	a.recentBlocksMu.Unlock()
	if !markAt.Equal(t0) || entries != maxBlockSentEntries {
		t.Fatalf("mark at %v with %d broadcast entries, want t0 with %d", markAt.Sub(t0), entries, maxBlockSentEntries)
	}
	all = append(all, registerDiscard(t, a, 1)...)
	tNew := t0.Add(30 * time.Second)
	fresh, _ := a.reserveBlock(ip, scopeBroadcast, all, tNew)
	if len(fresh) != len(all) {
		t.Fatalf("broadcast past the bound reached %d, want all %d", len(fresh), len(all))
	}
	if fresh, _ := a.reserveBlock(ip, scopeBroadcast, all, tNew.Add(time.Second)); len(fresh) != 0 {
		t.Fatalf("repeat after the new mark reached %d", len(fresh))
	}
	a.recentBlocksMu.Lock()
	r := a.recentBlocks[ip.String()]
	n, b := len(r.sent), r.bcastEntries
	a.recentBlocksMu.Unlock()
	if n != 0 || b != 0 {
		t.Fatalf("sent = %d, broadcast entries = %d after a new mark, want 0", n, b)
	}
}

// reserveBlockForTest returns only the fresh targets.
func (a *Analyzer) reserveBlockForTest(ip net.IP, scope blockScope, targets []*collectorStream, now time.Time) []*collectorStream {
	fresh, _ := a.reserveBlock(ip, scope, targets, now)
	return fresh
}
