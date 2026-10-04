package integration_test

import (
	"context"
	"net"
	"testing"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/analyzer"
	"PacketYeeter/pkg/grpctls"
	"PacketYeeter/pkg/grpctls/grpctlstest"
	"PacketYeeter/pkg/ratelimit"
)

// recvBlocks forwards every BLOCK_IP a collector stream receives.
func recvBlocks(stream apiv1.AnalyzerService_StreamSignalsClient) <-chan *apiv1.Command {
	out := make(chan *apiv1.Command, 16)
	go func() {
		for {
			cmd, err := stream.Recv()
			if err != nil {
				close(out)
				return
			}
			if cmd.GetType() == apiv1.CommandType_COMMAND_BLOCK_IP {
				out <- cmd
			}
		}
	}()
	return out
}

// fanoutBurst is the per-source burst of the zero-refill limiters the
// fan-out tests install, so whether a signal trips does not depend on timing.
const fanoutBurst = 200

// startFanoutAnalyzer runs an mTLS analyzer whose -scrub-client-names are
// scrub-a and scrub-b, with zero-refill rate limiters, and returns a dialer
// for clients by certificate name.
func startFanoutAnalyzer(t *testing.T) (*analyzer.Analyzer, func(name string) apiv1.AnalyzerServiceClient) {
	t.Helper()
	dir := t.TempDir()
	ca := grpctlstest.NewCA(t, "packetyeeter-ca")
	caFile := ca.WriteCA(t, dir, "ca")
	serverCert, serverKey := ca.IssueServer(t, "analyzer", "127.0.0.1").Write(t, dir, "analyzer")

	cfg := analyzer.Config{
		ListenAddr:     reserveTCPAddr(t),
		MetricsAddr:    reserveTCPAddr(t),
		JA4DBCachePath: writeJA4Cache(t),
		StateDir:       t.TempDir(),
		AIWorkers:      1,
		AIQueueSize:    100,
		EnableWatchAPI: true,
		TLS:            grpctls.ServerConfig{CertFile: serverCert, KeyFile: serverKey, ClientCAFile: caFile},
		// Isolate the rate-limit path: no reputation or AI blocks.
		ScrubClientNames:           []string{"scrub-a", "scrub-b"},
		ReputationThreshold:        1e9,
		AIConfidenceThreshold:      0.1,
		AIBlockScoreThreshold:      1e9,
		AISuspiciousScoreThreshold: 1e9,
		DisableDDoSCategory:        true,
	}
	a, err := analyzer.New(cfg)
	if err != nil {
		t.Fatalf("create analyzer: %v", err)
	}
	noRefill := 0.0
	limits := ratelimit.Config{IPRateExact: &noRefill, IPBurst: fanoutBurst}
	// Replace the limiters New() built; stop theirs so no cleanup goroutine leaks.
	a.RateLimiter.Stop()
	a.RateLimiter = ratelimit.NewLimiter(limits)
	if a.ScrubRateLimiter != nil {
		a.ScrubRateLimiter.Stop()
	}
	a.ScrubRateLimiter = ratelimit.NewLimiter(limits)
	if err := a.Start(); err != nil {
		t.Fatalf("start analyzer: %v", err)
	}
	t.Cleanup(a.Close)

	dial := func(name string) apiv1.AnalyzerServiceClient {
		cert, key := ca.IssueClient(t, name, name).Write(t, dir, name)
		return dialAnalyzer(t, a.Config.ListenAddr, grpctls.ClientConfig{CAFile: caFile, CertFile: cert, KeyFile: key})
	}
	return a, dial
}

func sendSignals(t *testing.T, src net.IP, n int, streams ...apiv1.AnalyzerService_StreamSignalsClient) {
	t.Helper()
	for range n {
		for _, s := range streams {
			if err := s.Send(&apiv1.Signal{
				Type:   apiv1.SignalType_SIGNAL_TCP_METADATA,
				Source: apiv1.SignalSource_SOURCE_EBPF,
				Ip:     src,
			}); err != nil {
				t.Fatalf("send signal: %v", err)
			}
		}
	}
}

// Two scrub collectors behind ECMP each see half of one source; the block is
// decided on the total, reaches both, not the host collector, and is
// published on WatchDecisions once.
func TestScrubBlockFanoutOverGRPC(t *testing.T) {
	_, dial := startFanoutAnalyzer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	watch, err := dial("controller").WatchDecisions(ctx, &apiv1.WatchRequest{Subscriber: "fanout"})
	if err != nil {
		t.Fatalf("open watch stream: %v", err)
	}
	decisions := make(chan *apiv1.Decision, 64)
	go func() {
		for {
			d, err := watch.Recv()
			if err != nil {
				close(decisions)
				return
			}
			decisions <- d
		}
	}()

	// The initial rule set confirms the analyzer registered the scrub role.
	scrubA := connectScrubCollector(t, ctx, dial("scrub-a"))
	recvRules(t, scrubA)
	scrubB := connectScrubCollector(t, ctx, dial("scrub-b"))
	recvRules(t, scrubB)
	host, err := dial("host-1").StreamSignals(ctx)
	if err != nil {
		t.Fatalf("open host stream: %v", err)
	}
	blocksA, blocksB, blocksHost := recvBlocks(scrubA), recvBlocks(scrubB), recvBlocks(host)

	// Each node alone stays at the burst; the total exceeds it.
	src := net.ParseIP("198.51.100.77").To4()
	sendSignals(t, src, fanoutBurst, scrubA, scrubB)

	for name, ch := range map[string]<-chan *apiv1.Command{"A": blocksA, "B": blocksB} {
		select {
		case cmd := <-ch:
			if !net.IP(cmd.GetIp()).Equal(src) {
				t.Fatalf("scrub %s blocked %v, want %v", name, net.IP(cmd.GetIp()), src)
			}
		case <-ctx.Done():
			t.Fatalf("scrub %s never received the block", name)
		}
	}

	blocksPublished := 0
	settle := time.After(500 * time.Millisecond)
	for done := false; !done; {
		select {
		case d := <-decisions:
			if d.GetCommand().GetType() == apiv1.CommandType_COMMAND_BLOCK_IP {
				blocksPublished++
			}
		case <-settle:
			done = true
		}
	}
	if blocksPublished != 1 {
		t.Fatalf("WatchDecisions published %d blocks, want 1", blocksPublished)
	}
	select {
	case cmd := <-blocksHost:
		t.Fatalf("host collector received %v; host blocks must stay per collector", cmd)
	default:
	}
}

func expectBlock(t *testing.T, ctx context.Context, name string, ch <-chan *apiv1.Command, want net.IP) {
	t.Helper()
	select {
	case cmd := <-ch:
		if !net.IP(cmd.GetIp()).Equal(want) {
			t.Fatalf("%s got block for %v, want %v", name, net.IP(cmd.GetIp()), want)
		}
	case <-ctx.Done():
		t.Fatalf("%s never received the block for %v", name, want)
	}
}

func expectNoBlock(t *testing.T, name string, ch <-chan *apiv1.Command) {
	t.Helper()
	select {
	case cmd := <-ch:
		t.Fatalf("%s received %v", name, cmd)
	case <-time.After(500 * time.Millisecond):
	}
}

// A collector with a valid certificate that is not on -scrub-client-names
// can announce scrub mode and trip the limiter for a victim, but the block
// stays on its own stream and never reaches the real scrub nodes.
func TestUntrustedScrubCannotFanOutOverGRPC(t *testing.T) {
	_, dial := startFanoutAnalyzer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	scrubA := connectScrubCollector(t, ctx, dial("scrub-a"))
	recvRules(t, scrubA)
	rogue := connectScrubCollector(t, ctx, dial("rogue-host"))
	recvRules(t, rogue)
	blocksA, blocksRogue := recvBlocks(scrubA), recvBlocks(rogue)

	victim := net.ParseIP("198.51.100.88").To4()
	sendSignals(t, victim, fanoutBurst+1, rogue)

	expectBlock(t, ctx, "rogue", blocksRogue, victim)
	expectNoBlock(t, "trusted scrub node", blocksA)
}

// An unlisted collector drains a victim's shared bucket without tripping it.
// Trusted scrub nodes that then report the victim trip only the shared
// limiter, so neither is blocked; trusted-only evidence still blocks both.
func TestUntrustedEvidenceCannotTriggerFanoutOverGRPC(t *testing.T) {
	_, dial := startFanoutAnalyzer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	scrubA := connectScrubCollector(t, ctx, dial("scrub-a"))
	recvRules(t, scrubA)
	scrubB := connectScrubCollector(t, ctx, dial("scrub-b"))
	recvRules(t, scrubB)
	rogue, err := dial("rogue-host").StreamSignals(ctx)
	if err != nil {
		t.Fatalf("open rogue stream: %v", err)
	}
	blocksA, blocksB, blocksRogue := recvBlocks(scrubA), recvBlocks(scrubB), recvBlocks(rogue)

	victim := net.ParseIP("198.51.100.99").To4()
	sendSignals(t, victim, fanoutBurst, rogue)
	// The analyzer handles a stream's signals in order and ends it only after
	// the last one, so once the rogue stream closes its evidence is in.
	if err := rogue.CloseSend(); err != nil {
		t.Fatalf("close rogue stream: %v", err)
	}
	select {
	case cmd, open := <-blocksRogue:
		if open {
			t.Fatalf("rogue received %v without crossing the limit", cmd)
		}
	case <-ctx.Done():
		t.Fatal("rogue stream never ended")
	}
	sendSignals(t, victim, 1, scrubA)
	sendSignals(t, victim, 1, scrubB)
	expectNoBlock(t, "scrub A", blocksA)
	expectNoBlock(t, "scrub B", blocksB)

	// Two trusted reports so far; fanoutBurst-1 more cross the trusted limit.
	sendSignals(t, victim, fanoutBurst-1, scrubA)
	expectBlock(t, ctx, "scrub A", blocksA, victim)
	expectBlock(t, ctx, "scrub B", blocksB, victim)
}
