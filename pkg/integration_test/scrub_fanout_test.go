package integration_test

import (
	"context"
	"net"
	"testing"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/analyzer"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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

// Two scrub collectors behind ECMP each see half of one source; the block is
// decided on the total, reaches both, not the host collector, and is
// published on WatchDecisions once.
func TestScrubBlockFanoutOverGRPC(t *testing.T) {
	a := startTestAnalyzer(t, func(cfg *analyzer.Config) {
		cfg.DryRun = false
		cfg.EnableWatchAPI = true
		// Isolate the rate-limit path: no reputation or AI blocks.
		cfg.ReputationThreshold = 1e9
		cfg.AIBlockScoreThreshold = 1e9
		cfg.AISuspiciousScoreThreshold = 1e9
		cfg.DisableDDoSCategory = true
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := grpc.NewClient(a.Config.ListenAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("create grpc client: %v", err)
	}
	defer conn.Close()
	client := apiv1.NewAnalyzerServiceClient(conn)

	watch, err := client.WatchDecisions(ctx, &apiv1.WatchRequest{Subscriber: "fanout"})
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
	scrubA := connectScrubCollector(t, ctx, client)
	recvRules(t, scrubA)
	scrubB := connectScrubCollector(t, ctx, client)
	recvRules(t, scrubB)
	host, err := client.StreamSignals(ctx)
	if err != nil {
		t.Fatalf("open host stream: %v", err)
	}
	blocksA, blocksB, blocksHost := recvBlocks(scrubA), recvBlocks(scrubB), recvBlocks(host)

	// Default per-IP burst is 200: each node alone stays at it, the total
	// exceeds it.
	src := net.ParseIP("198.51.100.77").To4()
	for range 200 {
		for _, s := range []apiv1.AnalyzerService_StreamSignalsClient{scrubA, scrubB} {
			if err := s.Send(&apiv1.Signal{
				Type:   apiv1.SignalType_SIGNAL_TCP_METADATA,
				Source: apiv1.SignalSource_SOURCE_EBPF,
				Ip:     src,
			}); err != nil {
				t.Fatalf("send signal: %v", err)
			}
		}
	}

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
