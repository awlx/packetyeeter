package analyzer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/analyzer/reputation"
	"PacketYeeter/pkg/metrics"
	"PacketYeeter/pkg/ratelimit"
)

const trustedScrubName = "scrub.example.net"

// allowScrubNames sets -scrub-client-names after New, which would otherwise
// demand mTLS files the unit tests do not need.
func allowScrubNames(a *Analyzer) {
	a.Config.ScrubClientNames = []string{trustedScrubName}
}

// certCtx is a stream context whose peer presented a verified certificate
// with CommonName cn; "" means no certificate.
func certCtx(cn string) context.Context {
	ctx := context.Background()
	if cn == "" {
		return ctx
	}
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
	return peer.NewContext(ctx, &peer.Peer{
		Addr:     &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)},
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}},
	})
}

func registerStream(t *testing.T, a *Analyzer, role, cn string, stream apiv1.AnalyzerService_StreamSignalsServer) *collectorStream {
	t.Helper()
	cs := &collectorStream{stream: stream}
	if role != "" {
		cs.setRole(role)
	}
	if id := a.registerCollector(certCtx(cn), cs); id == "" {
		t.Fatal("collector not admitted")
	}
	return cs
}

func newBufferedFake(n int) *fakeCollectorStream {
	return &fakeCollectorStream{sent: make(chan *apiv1.Command, n)}
}

// registerRole registers a collector without a trusted certificate.
func registerRole(t *testing.T, a *Analyzer, role string) (*collectorStream, *fakeCollectorStream) {
	t.Helper()
	fake := newFakeCollectorStream()
	return registerStream(t, a, role, "", fake), fake
}

// registerTrusted registers a collector whose certificate is on
// -scrub-client-names.
func registerTrusted(t *testing.T, a *Analyzer, role string) (*collectorStream, *fakeCollectorStream) {
	t.Helper()
	fake := newBufferedFake(16)
	return registerStream(t, a, role, trustedScrubName, fake), fake
}

// stalledStream blocks every Send until released.
type stalledStream struct {
	apiv1.AnalyzerService_StreamSignalsServer
	entered chan struct{}
	release chan struct{}
}

func newStalledStream(t *testing.T) *stalledStream {
	s := &stalledStream{entered: make(chan struct{}, 1), release: make(chan struct{})}
	t.Cleanup(func() { close(s.release) })
	return s
}

func (s *stalledStream) Send(*apiv1.Command) error {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	<-s.release
	return nil
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func unblockCmd(ip string) *apiv1.Command {
	return &apiv1.Command{Type: apiv1.CommandType_COMMAND_UNBLOCK_IP, Ip: net.ParseIP(ip).To4()}
}

func TestScrubBlockReachesEveryTrustedScrubCollectorOnce(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})
	allowScrubNames(a)
	w := startWatch(t, a, "ctl", nil, 8)

	scrubA, fakeA := registerTrusted(t, a, "scrub")
	scrubB, fakeB := registerTrusted(t, a, "scrub")
	_, host := registerTrusted(t, a, "host")
	_, untrusted := registerRole(t, a, "scrub")

	before := testutil.ToFloat64(metrics.ScrubCommandFanout)
	a.sendCommand(scrubA, blockCmd("192.0.2.20"), true)

	for name, f := range map[string]*fakeCollectorStream{"origin": fakeA, "peer": fakeB} {
		if got := f.waitForCommand(t); got.GetType() != apiv1.CommandType_COMMAND_BLOCK_IP ||
			!net.IP(got.GetIp()).Equal(net.ParseIP("192.0.2.20")) {
			t.Fatalf("%s scrub collector got %v, want BLOCK_IP 192.0.2.20", name, got)
		}
	}
	host.expectNoCommand(t)
	untrusted.expectNoCommand(t)

	if d := w.next(t); d.GetCommand().GetType() != apiv1.CommandType_COMMAND_BLOCK_IP {
		t.Fatalf("decision = %v, want the block", d)
	}
	w.expectNone(t)
	waitFor(t, "fan-out counter", func() bool {
		return testutil.ToFloat64(metrics.ScrubCommandFanout)-before == 1
	})

	// Dedup covers the whole fan-out: the peer crossing the threshold next
	// must not re-send.
	a.sendCommand(scrubB, blockCmd("192.0.2.20"), true)
	fakeA.expectNoCommand(t)
	fakeB.expectNoCommand(t)
	w.expectNone(t)
	if got := testutil.ToFloat64(metrics.ScrubCommandFanout) - before; got != 1 {
		t.Fatalf("fan-out sends = %v, want 1", got)
	}
}

// A stream that announces scrub mode without a listed certificate keeps its
// own block but cannot push it to the real scrub nodes.
func TestUntrustedScrubOriginDoesNotFanOut(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})
	allowScrubNames(a)

	_, peerFake := registerTrusted(t, a, "scrub")
	for name, cn := range map[string]string{"no certificate": "", "unlisted certificate": "other.example.net"} {
		fake := newFakeCollectorStream()
		rogue := registerStream(t, a, "scrub", cn, fake)
		a.sendCommand(rogue, blockCmd("192.0.2.30"), true)
		if got := fake.waitForCommand(t); got.GetType() != apiv1.CommandType_COMMAND_BLOCK_IP {
			t.Fatalf("%s: origin got %v, want its own block", name, got)
		}
		peerFake.expectNoCommand(t)
		a.recentBlocksMu.Lock()
		delete(a.recentBlocks, "192.0.2.30")
		a.recentBlocksMu.Unlock()
	}
}

func TestUntrustedScrubPeerReceivesNothing(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})
	allowScrubNames(a)

	origin, fakeOrigin := registerTrusted(t, a, "scrub")
	other := newFakeCollectorStream()
	registerStream(t, a, "scrub", "other.example.net", other)
	_, noCert := registerRole(t, a, "scrub")

	a.sendCommand(origin, blockCmd("192.0.2.31"), true)
	fakeOrigin.waitForCommand(t)
	other.expectNoCommand(t)
	noCert.expectNoCommand(t)
}

func TestEmptyScrubAllowlistDisablesFanout(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})

	origin, fakeOrigin := registerTrusted(t, a, "scrub")
	_, peerFake := registerTrusted(t, a, "scrub")
	if origin.certTrusted {
		t.Fatal("certificate trusted with an empty -scrub-client-names")
	}

	a.sendCommand(origin, blockCmd("192.0.2.32"), true)
	fakeOrigin.waitForCommand(t)
	peerFake.expectNoCommand(t)
}

func TestScrubFanoutStalledPeerDoesNotDelayOrigin(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})
	allowScrubNames(a)

	fakeOrigin := newBufferedFake(64)
	origin := registerStream(t, a, "scrub", trustedScrubName, fakeOrigin)
	stalled := newStalledStream(t)
	registerStream(t, a, "scrub", trustedScrubName, stalled)
	_, healthy := registerTrusted(t, a, "scrub")

	for i := range 10 {
		start := time.Now()
		a.sendCommand(origin, blockCmd(fmt.Sprintf("192.0.2.%d", 100+i)), true)
		if d := time.Since(start); d > 250*time.Millisecond {
			t.Fatalf("command %d took %v with a stalled peer", i, d)
		}
		if i == 0 {
			<-stalled.entered
		}
		fakeOrigin.waitForCommand(t)
		if got := healthy.waitForCommand(t); !net.IP(got.GetIp()).Equal(net.ParseIP(fmt.Sprintf("192.0.2.%d", 100+i))) {
			t.Fatalf("healthy peer got %v for command %d", got, i)
		}
	}
}

func TestScrubFanoutKeepsPerPeerOrder(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})
	allowScrubNames(a)

	origin := registerStream(t, a, "scrub", trustedScrubName, newBufferedFake(512))
	peerFake := newBufferedFake(512)
	registerStream(t, a, "scrub", trustedScrubName, peerFake)

	var want []*apiv1.Command
	for i := range 100 {
		ip := fmt.Sprintf("10.0.%d.%d", i/250, i%250)
		for _, cmd := range []*apiv1.Command{blockCmd(ip), unblockCmd(ip)} {
			want = append(want, cmd)
			a.sendCommand(origin, cmd, true)
		}
	}
	for i, w := range want {
		got := peerFake.waitForCommand(t)
		if got.GetType() != w.GetType() || !net.IP(got.GetIp()).Equal(net.IP(w.GetIp())) {
			t.Fatalf("peer command %d = %v %v, want %v %v", i, got.GetType(), net.IP(got.GetIp()), w.GetType(), net.IP(w.GetIp()))
		}
	}
}

func TestScrubFanoutQueueOverflowDrops(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})
	allowScrubNames(a)

	origin := registerStream(t, a, "scrub", trustedScrubName, newBufferedFake(512))
	stalled := newStalledStream(t)
	registerStream(t, a, "scrub", trustedScrubName, stalled)

	a.sendCommand(origin, unblockCmd("192.0.2.40"), true)
	<-stalled.entered // the worker holds this one; the queue is empty

	before := testutil.ToFloat64(metrics.ScrubCommandFanoutDropped.WithLabelValues("queue_full"))
	const extra = 20
	for range scrubFanoutQueueSize + extra {
		a.sendCommand(origin, unblockCmd("192.0.2.40"), true)
	}
	if got := testutil.ToFloat64(metrics.ScrubCommandFanoutDropped.WithLabelValues("queue_full")) - before; got != extra {
		t.Fatalf("dropped = %v, want %d", got, extra)
	}
}

func TestScrubRoleChangeLeavesFanout(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})
	allowScrubNames(a)

	origin, fakeOrigin := registerTrusted(t, a, "scrub")
	peerCS, peerFake := registerTrusted(t, a, "scrub")

	a.sendCommand(origin, blockCmd("192.0.2.50"), true)
	fakeOrigin.waitForCommand(t)
	peerFake.waitForCommand(t)

	peerCS.setRole("host")
	a.sendCommand(origin, blockCmd("192.0.2.51"), true)
	fakeOrigin.waitForCommand(t)
	peerFake.expectNoCommand(t)

	// A former scrub origin no longer fans out either.
	peerCS.setRole("scrub")
	origin.setRole("host")
	a.sendCommand(origin, blockCmd("192.0.2.52"), true)
	fakeOrigin.waitForCommand(t)
	peerFake.expectNoCommand(t)
}

func TestScrubBlockFanoutRespectsDryRun(t *testing.T) {
	a := newWatchAnalyzer(t, Config{DryRun: true})
	allowScrubNames(a)
	w := startWatch(t, a, "ctl", nil, 8)

	scrubA, fakeA := registerTrusted(t, a, "scrub")
	_, fakeB := registerTrusted(t, a, "scrub")

	a.sendCommand(scrubA, blockCmd("192.0.2.21"), true)
	fakeA.expectNoCommand(t)
	fakeB.expectNoCommand(t)
	w.expectNone(t)
}

func TestScrubBlockFanoutRespectsKillSwitch(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})
	allowScrubNames(a)
	scrubA, fakeA := registerTrusted(t, a, "scrub")
	_, fakeB := registerTrusted(t, a, "scrub")

	a.enforcement.Stop("test")
	a.sendCommand(scrubA, blockCmd("192.0.2.22"), true)
	fakeA.expectNoCommand(t)
	fakeB.expectNoCommand(t)
}

func TestHostBlockStaysOnOriginCollector(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})
	allowScrubNames(a)
	w := startWatch(t, a, "ctl", nil, 8)

	// An unannounced role is host mode (collectors before scrub mode).
	hostA, fakeA := registerTrusted(t, a, "")
	_, fakeB := registerTrusted(t, a, "host")
	_, scrub := registerTrusted(t, a, "scrub")

	a.sendCommand(hostA, blockCmd("192.0.2.23"), true)
	fakeA.waitForCommand(t)
	fakeB.expectNoCommand(t)
	scrub.expectNoCommand(t)
	if d := w.next(t); d.GetCommand().GetType() != apiv1.CommandType_COMMAND_BLOCK_IP {
		t.Fatalf("decision = %v, want the block", d)
	}
	w.expectNone(t)
}

// setZeroRefillLimiters swaps in shared and trusted limiters that never
// refill, so tests trip them after exactly burst signals per source.
func setZeroRefillLimiters(a *Analyzer, burst float64) {
	noRefill := 0.0
	cfg := ratelimit.Config{IPRateExact: &noRefill, IPBurst: burst}
	for _, old := range []*ratelimit.Limiter{a.RateLimiter, a.ScrubRateLimiter} {
		if old != nil {
			old.Stop()
		}
	}
	a.RateLimiter = ratelimit.NewLimiter(cfg)
	a.ScrubRateLimiter = ratelimit.NewLimiter(cfg)
}

func tcpSignal(ip string) *apiv1.Signal {
	return &apiv1.Signal{
		Type:   apiv1.SignalType_SIGNAL_TCP_METADATA,
		Source: apiv1.SignalSource_SOURCE_EBPF,
		Ip:     net.ParseIP(ip).To4(),
	}
}

func newRateLimitAnalyzer(t *testing.T) *Analyzer {
	t.Helper()
	a := newTestAnalyzer(t)
	allowScrubNames(a)
	a.AIEngine = nil
	a.Config.ReputationThreshold = 1e9
	setZeroRefillLimiters(a, 10)
	return a
}

// A collector outside the allowlist drains a victim's shared bucket without
// tripping it. Trusted scrub nodes then trip the shared limiter whenever they
// report the victim, but block only on their own trusted-only verdict: the
// untrusted evidence gets the victim blocked on no scrub node.
func TestUntrustedEvidenceCannotTriggerFanout(t *testing.T) {
	for name, rogueCN := range map[string]string{"host without certificate": "", "unlisted certificate": "other.example.net"} {
		t.Run(name, func(t *testing.T) {
			a := newRateLimitAnalyzer(t)
			rogueFake := newBufferedFake(16)
			rogue := registerStream(t, a, "host", rogueCN, rogueFake)
			scrubA, fakeA := registerTrusted(t, a, "scrub")
			scrubB, fakeB := registerTrusted(t, a, "scrub")
			victim := net.ParseIP("198.51.100.9")

			for range 10 {
				a.processSignal(tcpSignal("198.51.100.9"), rogue)
			}
			rogueFake.expectNoCommand(t)

			skipped := testutil.ToFloat64(metrics.ScrubSharedOnlyBlocksSkipped.WithLabelValues("rate_limit"))
			a.processSignal(tcpSignal("198.51.100.9"), scrubA)
			a.processSignal(tcpSignal("198.51.100.9"), scrubB)
			fakeA.expectNoCommand(t)
			fakeB.expectNoCommand(t)
			if got := testutil.ToFloat64(metrics.ScrubSharedOnlyBlocksSkipped.WithLabelValues("rate_limit")) - skipped; got != 2 {
				t.Fatalf("skipped shared-only blocks = %v, want 2", got)
			}

			// The untrusted contributor itself is still blocked locally.
			a.processSignal(tcpSignal("198.51.100.9"), rogue)
			if got := rogueFake.waitForCommand(t); !net.IP(got.GetIp()).Equal(victim) {
				t.Fatalf("rogue got %v, want its local block", got)
			}
			fakeA.expectNoCommand(t)
			fakeB.expectNoCommand(t)

			// Trusted evidence alone (A's and B's reports so far plus 8 more
			// fill the burst of 10; the next trips) still blocks and fans out.
			for range 8 {
				a.processSignal(tcpSignal("198.51.100.9"), scrubA)
			}
			fakeA.expectNoCommand(t)
			a.processSignal(tcpSignal("198.51.100.9"), scrubA)
			for name, f := range map[string]*fakeCollectorStream{"A": fakeA, "B": fakeB} {
				if got := f.waitForCommand(t); !net.IP(got.GetIp()).Equal(victim) {
					t.Fatalf("scrub %s got %v, want the trusted block", name, got)
				}
			}
			rogueFake.expectNoCommand(t)
		})
	}
}

// A local block reserved by an untrusted stream must not swallow a trusted
// fan-out decision for the same source within the dedup TTL.
func TestLocalBlockDoesNotSuppressTrustedFanout(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})
	allowScrubNames(a)
	w := startWatch(t, a, "ctl", nil, 8)

	rogue, rogueFake := registerRole(t, a, "scrub")
	scrubA, fakeA := registerTrusted(t, a, "scrub")
	scrubB, fakeB := registerTrusted(t, a, "scrub")
	_, fakeC := registerTrusted(t, a, "scrub")

	a.sendCommand(rogue, blockCmd("192.0.2.60"), true)
	rogueFake.waitForCommand(t)
	w.next(t)

	a.sendCommand(scrubA, blockCmd("192.0.2.60"), true)
	for name, f := range map[string]*fakeCollectorStream{"origin": fakeA, "peer B": fakeB, "peer C": fakeC} {
		if got := f.waitForCommand(t); !net.IP(got.GetIp()).Equal(net.ParseIP("192.0.2.60")) {
			t.Fatalf("%s got %v, want the block", name, got)
		}
	}
	rogueFake.expectNoCommand(t)
	w.next(t)

	// The fan-out is now reserved: repeats are suppressed.
	a.sendCommand(scrubB, blockCmd("192.0.2.60"), true)
	a.sendCommand(rogue, blockCmd("192.0.2.60"), true)
	for _, f := range []*fakeCollectorStream{fakeA, fakeB, fakeC, rogueFake} {
		f.expectNoCommand(t)
	}
	w.expectNone(t)
}

func TestFanoutIneligibleDecisionStaysLocal(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})
	allowScrubNames(a)
	origin, fakeOrigin := registerTrusted(t, a, "scrub")
	_, peerFake := registerTrusted(t, a, "scrub")

	a.sendCommand(origin, blockCmd("192.0.2.61"), false)
	fakeOrigin.waitForCommand(t)
	peerFake.expectNoCommand(t)
}

// With -scrub-broadcast-requires-trusted-evidence, Broadcast reaches trusted
// scrub nodes only for sources a trusted scrub stream reported.
func TestBroadcastNeedsTrustedEvidenceForScrubNodes(t *testing.T) {
	a := newRateLimitAnalyzer(t)
	enableBroadcastGate(a)
	rogue, rogueFake := registerRole(t, a, "host")
	scrubA, fakeA := registerTrusted(t, a, "scrub")

	// Evidence from the untrusted stream only.
	a.processSignal(tcpSignal("198.51.100.70"), rogue)
	a.Broadcast(blockCmd("198.51.100.70"))
	rogueFake.waitForCommand(t)
	fakeA.expectNoCommand(t)

	// A local reservation does not suppress a later Broadcast, and trusted
	// evidence lets it reach the scrub node.
	a.sendCommand(rogue, blockCmd("198.51.100.71"), false)
	rogueFake.waitForCommand(t)
	a.processSignal(tcpSignal("198.51.100.71"), scrubA)
	a.Broadcast(blockCmd("198.51.100.71"))
	if got := fakeA.waitForCommand(t); !net.IP(got.GetIp()).Equal(net.ParseIP("198.51.100.71")) {
		t.Fatalf("scrub node got %v, want the broadcast block", got)
	}
	rogueFake.expectNoCommand(t)
}

// A source split across trusted scrub nodes is judged on their total
// trusted evidence.
func TestSplitSourceAcrossScrubNodesJudgedOnTotal(t *testing.T) {
	a := newTestAnalyzer(t)
	allowScrubNames(a)
	a.AIEngine = nil
	a.Config.ReputationThreshold = 1e9
	setZeroRefillLimiters(a, 10)
	// No shared limiter: only the trusted-only limiter can trip, so the
	// block below rests on trusted evidence alone.
	a.RateLimiter.Stop()
	a.RateLimiter = nil

	scrubA, fakeA := registerTrusted(t, a, "scrub")
	scrubB, fakeB := registerTrusted(t, a, "scrub")

	signal := func(ip string) *apiv1.Signal {
		return &apiv1.Signal{
			Type:   apiv1.SignalType_SIGNAL_TCP_METADATA,
			Source: apiv1.SignalSource_SOURCE_EBPF,
			Ip:     net.ParseIP(ip).To4(),
		}
	}

	// Control: 6 signals from one node alone stay under the burst of 10.
	for range 6 {
		a.processSignal(signal("198.51.100.1"), scrubA)
	}
	fakeA.expectNoCommand(t)
	fakeB.expectNoCommand(t)

	// 6 + 6 from two nodes exceed it.
	for range 6 {
		a.processSignal(signal("198.51.100.2"), scrubA)
		a.processSignal(signal("198.51.100.2"), scrubB)
	}
	for name, f := range map[string]*fakeCollectorStream{"A": fakeA, "B": fakeB} {
		got := f.waitForCommand(t)
		if !net.IP(got.GetIp()).Equal(net.ParseIP("198.51.100.2")) {
			t.Fatalf("node %s got %v, want BLOCK_IP 198.51.100.2", name, got)
		}
	}
	fakeA.expectNoCommand(t)
	fakeB.expectNoCommand(t)
}

// With fan-out off, each scrub node's own decision still reaches it: the
// dedup is per collector, so one node's block does not swallow another's.
func TestLocalDecisionsOnSeveralNodesEachDeliver(t *testing.T) {
	for name, trusted := range map[string]bool{"allowlist empty": false, "not fan-out eligible": true} {
		t.Run(name, func(t *testing.T) {
			a := newWatchAnalyzer(t, Config{})
			register := registerRole
			if trusted {
				allowScrubNames(a)
				register = registerTrusted
			}
			w := startWatch(t, a, "ctl", nil, 8)
			scrubA, fakeA := register(t, a, "scrub")
			scrubB, fakeB := register(t, a, "scrub")

			a.sendCommand(scrubA, blockCmd("192.0.2.80"), false)
			fakeA.waitForCommand(t)
			fakeB.expectNoCommand(t)
			a.sendCommand(scrubB, blockCmd("192.0.2.80"), false)
			fakeB.waitForCommand(t)
			fakeA.expectNoCommand(t)

			// Each node again within the TTL: duplicates.
			a.sendCommand(scrubA, blockCmd("192.0.2.80"), false)
			a.sendCommand(scrubB, blockCmd("192.0.2.80"), false)
			fakeA.expectNoCommand(t)
			fakeB.expectNoCommand(t)

			// Published once per scope, not once per node.
			w.next(t)
			w.expectNone(t)

			r := liveReservation(a, net.ParseIP("192.0.2.80"))
			if r == nil || publishedScopes(r) != scopeLocal || len(r.sent) != 2 {
				t.Fatalf("reservation = %+v, want local scope sent to 2 collectors", r)
			}
		})
	}
}

// With -scrub-broadcast-requires-trusted-evidence, a Broadcast judged on
// untrusted evidence reaches only non-scrub collectors; once a trusted scrub stream reports the source, a repeat
// Broadcast within the TTL reaches the scrub nodes and not the others again.
func TestRepeatBroadcastReachesNewlyEligibleScrubNodes(t *testing.T) {
	a := newRateLimitAnalyzer(t)
	enableBroadcastGate(a)
	host, hostFake := registerRole(t, a, "host")
	scrubA, fakeA := registerTrusted(t, a, "scrub")
	_, fakeB := registerTrusted(t, a, "scrub")

	a.processSignal(tcpSignal("198.51.100.90"), host)
	a.Broadcast(blockCmd("198.51.100.90"))
	hostFake.waitForCommand(t)
	fakeA.expectNoCommand(t)
	fakeB.expectNoCommand(t)

	a.processSignal(tcpSignal("198.51.100.90"), scrubA)
	a.Broadcast(blockCmd("198.51.100.90"))
	for name, f := range map[string]*fakeCollectorStream{"A": fakeA, "B": fakeB} {
		if got := f.waitForCommand(t); !net.IP(got.GetIp()).Equal(net.ParseIP("198.51.100.90")) {
			t.Fatalf("scrub %s got %v, want the broadcast block", name, got)
		}
	}
	hostFake.expectNoCommand(t)

	a.Broadcast(blockCmd("198.51.100.90"))
	for _, f := range []*fakeCollectorStream{hostFake, fakeA, fakeB} {
		f.expectNoCommand(t)
	}
	r := liveReservation(a, net.ParseIP("198.51.100.90"))
	if r == nil || publishedScopes(r) != scopeBroadcast || len(r.sent) != 3 {
		t.Fatalf("reservation = %+v, want broadcast scope sent to 3 collectors", r)
	}
}

// Reputation blocks fan out only when trusted scrub evidence alone puts the
// source over the threshold.
func TestScrubReputationGatesReputationFanout(t *testing.T) {
	setup := func(t *testing.T) (*Analyzer, *collectorStream, *fakeCollectorStream, *fakeCollectorStream) {
		a := newTestAnalyzer(t)
		allowScrubNames(a)
		a.AIEngine = nil
		a.Config.ReputationThreshold = 50
		a.RateLimiter = nil
		srep := reputation.New(time.Hour, 0.95, 50)
		t.Cleanup(srep.Stop)
		a.ScrubReputation = srep
		origin, fakeOrigin := registerTrusted(t, a, "scrub")
		_, peerFake := registerTrusted(t, a, "scrub")
		return a, origin, fakeOrigin, peerFake
	}

	t.Run("mixed evidence blocks no trusted scrub node", func(t *testing.T) {
		a, origin, fakeOrigin, peerFake := setup(t)
		a.Reputation.Penalize("198.51.100.100", reputation.TypeIP, 80, "untrusted")
		a.ScrubReputation.Penalize("198.51.100.100", reputation.TypeIP, 20, "trusted")
		a.processSignal(tcpSignal("198.51.100.100"), origin)
		fakeOrigin.expectNoCommand(t)
		peerFake.expectNoCommand(t)

		// A host collector still blocks on the shared score.
		host, hostFake := registerRole(t, a, "host")
		a.processSignal(tcpSignal("198.51.100.100"), host)
		hostFake.waitForCommand(t)
		fakeOrigin.expectNoCommand(t)
		peerFake.expectNoCommand(t)
	})

	t.Run("trusted evidence fans out", func(t *testing.T) {
		a, origin, fakeOrigin, peerFake := setup(t)
		a.Reputation.Penalize("198.51.100.101", reputation.TypeIP, 80, "trusted")
		a.ScrubReputation.Penalize("198.51.100.101", reputation.TypeIP, 80, "trusted")
		a.processSignal(tcpSignal("198.51.100.101"), origin)
		fakeOrigin.waitForCommand(t)
		peerFake.waitForCommand(t)
	})

	t.Run("untrusted stream cannot fan out", func(t *testing.T) {
		a, _, fakeOrigin, peerFake := setup(t)
		rogue, rogueFake := registerRole(t, a, "scrub")
		a.Reputation.Penalize("198.51.100.102", reputation.TypeIP, 80, "x")
		a.ScrubReputation.Penalize("198.51.100.102", reputation.TypeIP, 80, "x")
		a.processSignal(tcpSignal("198.51.100.102"), rogue)
		rogueFake.waitForCommand(t)
		fakeOrigin.expectNoCommand(t)
		peerFake.expectNoCommand(t)
	})

	t.Run("only trusted rate-limit trips feed it", func(t *testing.T) {
		a, _, _, _ := setup(t)
		a.penalizeRateLimited(net.ParseIP("198.51.100.103"), false)
		if got := a.ScrubReputation.GetScore("198.51.100.103", reputation.TypeIP); got != 0 {
			t.Fatalf("untrusted trip raised trusted reputation to %v", got)
		}
		a.penalizeRateLimited(net.ParseIP("198.51.100.103"), true)
		if got := a.ScrubReputation.GetScore("198.51.100.103", reputation.TypeIP); got <= 0 {
			t.Fatalf("trusted trip left trusted reputation at %v", got)
		}
	})
}

// A trip of the trusted-only limiter alone is counted like a shared trip.
func TestTrustedOnlyTripRecordsRateLimitMetrics(t *testing.T) {
	a := newTestAnalyzer(t)
	allowScrubNames(a)
	a.AIEngine = nil
	a.Config.ReputationThreshold = 1e9
	noRefill := 0.0
	a.ScrubRateLimiter = ratelimit.NewLimiter(ratelimit.Config{IPRateExact: &noRefill, IPBurst: 1})
	origin, fakeOrigin := registerTrusted(t, a, "scrub")
	_, peerFake := registerTrusted(t, a, "scrub")

	before := testutil.ToFloat64(metrics.RateLimitExceeded.WithLabelValues("ip"))
	a.processSignal(tcpSignal("198.51.100.110"), origin)
	a.processSignal(tcpSignal("198.51.100.110"), origin)
	fakeOrigin.waitForCommand(t)
	peerFake.waitForCommand(t)
	if got := testutil.ToFloat64(metrics.RateLimitExceeded.WithLabelValues("ip")) - before; got != 1 {
		t.Fatalf("rate-limit trips counted = %v, want 1", got)
	}
}

// gateStream blocks Send until its gate closes.
type gateStream struct {
	apiv1.AnalyzerService_StreamSignalsServer
	entered chan struct{}
	gate    chan struct{}
}

func (s *gateStream) Send(*apiv1.Command) error {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	<-s.gate
	return nil
}

func TestScrubFanoutCountsQueuedCommandsOfGonePeer(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})
	allowScrubNames(a)
	origin := registerStream(t, a, "scrub", trustedScrubName, newBufferedFake(64))

	peerStream := &gateStream{entered: make(chan struct{}, 1), gate: make(chan struct{})}
	ctx, cancel := context.WithCancel(certCtx(trustedScrubName))
	defer cancel()
	peerCS := &collectorStream{stream: peerStream}
	peerCS.setRole("scrub")
	id := a.registerCollector(ctx, peerCS)
	if id == "" {
		t.Fatal("peer not admitted")
	}

	a.sendCommand(origin, blockCmd("192.0.2.90"), true)
	<-peerStream.entered
	for i := range 3 {
		a.sendCommand(origin, blockCmd(fmt.Sprintf("192.0.2.%d", 91+i)), true)
	}
	before := testutil.ToFloat64(metrics.ScrubCommandFanoutDropped.WithLabelValues("peer_gone"))
	a.unregisterCollector(id)
	cancel()
	close(peerStream.gate)
	waitFor(t, "queued commands counted", func() bool {
		return testutil.ToFloat64(metrics.ScrubCommandFanoutDropped.WithLabelValues("peer_gone"))-before == 3
	})
}

// A fan-out enqueued after the peer's worker drained its queue is counted,
// not silently lost.
func TestFanoutEnqueueAfterDrainCountsPeerGone(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})
	cs := &collectorStream{fanout: make(chan scrubFanoutItem, 4)}
	drainScrubFanout(cs)
	if !cs.fanoutIsClosed() {
		t.Fatal("drained stream not marked closed")
	}
	before := testutil.ToFloat64(metrics.ScrubCommandFanoutDropped.WithLabelValues("peer_gone"))
	a.enqueueScrubFanout(cs, blockCmd("192.0.2.95"), time.Time{})
	if got := testutil.ToFloat64(metrics.ScrubCommandFanoutDropped.WithLabelValues("peer_gone")) - before; got != 1 {
		t.Fatalf("peer_gone delta = %v, want 1", got)
	}
	if len(cs.fanout) != 0 {
		t.Fatal("command queued on a closed stream")
	}
}
