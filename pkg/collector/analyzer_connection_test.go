package collector

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	apiv1 "PacketYeeter/api/proto/v1"
)

func TestAnalyzerReconnectBackoffGrowsForUnstableStreams(t *testing.T) {
	delay, next := analyzerReconnectBackoff(time.Second, time.Millisecond)
	if delay != time.Second || next != 2*time.Second {
		t.Fatalf("first unstable reconnect = (%v, %v), want (1s, 2s)", delay, next)
	}

	delay, next = analyzerReconnectBackoff(next, time.Millisecond)
	if delay != 2*time.Second || next != 4*time.Second {
		t.Fatalf("second unstable reconnect = (%v, %v), want (2s, 4s)", delay, next)
	}

	delay, next = analyzerReconnectBackoff(analyzerReconnectMax, time.Millisecond)
	if delay != analyzerReconnectMax || next != analyzerReconnectMax {
		t.Fatalf("capped reconnect = (%v, %v), want (%v, %v)",
			delay, next, analyzerReconnectMax, analyzerReconnectMax)
	}
}

func TestAnalyzerReconnectBackoffResetsAfterStableStream(t *testing.T) {
	delay, next := analyzerReconnectBackoff(analyzerReconnectMax, analyzerConnectionStable)
	if delay != analyzerReconnectInitial || next != 2*analyzerReconnectInitial {
		t.Fatalf("stable reconnect = (%v, %v), want (1s, 2s)", delay, next)
	}
}

// holdStreamAnalyzer keeps every stream open until the client goes away. With
// rules set it first sends that rule set, as the analyzer does when a scrub
// collector announces its role.
type holdStreamAnalyzer struct {
	apiv1.UnimplementedAnalyzerServiceServer
	rules *apiv1.RuleSetDelta
}

func (h holdStreamAnalyzer) StreamSignals(stream apiv1.AnalyzerService_StreamSignalsServer) error {
	if h.rules != nil {
		if _, err := stream.Recv(); err != nil { // role signal
			return err
		}
		if err := stream.Send(&apiv1.Command{Type: apiv1.CommandType_COMMAND_SET_RULES, Rules: h.rules}); err != nil {
			return err
		}
	}
	<-stream.Context().Done()
	return nil
}

func startAnalyzerConnection(t *testing.T, addr string) *Collector {
	t.Helper()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	c, err := New(Config{AnalyzerAddr: addr}, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.rules = newRuleEngine(newFakeRuleMaps())
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.wg.Add(1)
	go c.manageAnalyzerConnection()
	t.Cleanup(func() {
		c.cancel()
		c.wg.Wait()
		c.mu.Lock()
		if c.analyzerConn != nil {
			c.analyzerConn.Close()
		}
		c.mu.Unlock()
	})
	return c
}

func listenAnalyzer(t *testing.T, impl apiv1.AnalyzerServiceServer) (*grpc.Server, string) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	apiv1.RegisterAnalyzerServiceServer(srv, impl)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return srv, lis.Addr().String()
}

func TestManageAnalyzerConnectionTracksReadiness(t *testing.T) {
	srv, addr := listenAnalyzer(t, holdStreamAnalyzer{rules: &apiv1.RuleSetDelta{Replace: true}})
	c := startAnalyzerConnection(t, addr)

	waitUp := func(want bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if up, _ := c.analyzerReady.status(); up == want {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("analyzer stream up never became %v", want)
	}
	waitUp(true)
	srv.Stop()
	waitUp(false)
}

func TestManageAnalyzerConnectionNotUpWithoutRules(t *testing.T) {
	_, addr := listenAnalyzer(t, holdStreamAnalyzer{})
	c := startAnalyzerConnection(t, addr)

	deadline := time.Now().Add(5 * time.Second)
	for !c.connected.Load() {
		if time.Now().After(deadline) {
			t.Fatal("never connected")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if up, _ := c.analyzerReady.status(); up {
		t.Fatal("stream without rules reported up")
	}
}

func TestApplyRulesMarksSynced(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	c := &Collector{Logger: logger, rules: newRuleEngine(newFakeRuleMaps()), analyzerReady: newAnalyzerReadiness(time.Minute)}
	c.analyzerReady.set(true)

	dup := &apiv1.RuleSetDelta{Replace: true, Upsert: []*apiv1.Rule{
		testRule("a", "192.0.2.0/24", 1), testRule("a", "198.51.100.0/24", 2),
	}}
	c.applyRules(dup)
	if up, _ := c.analyzerReady.status(); up {
		t.Fatal("rejected rule set marked the stream synced")
	}

	c.applyRules(&apiv1.RuleSetDelta{Replace: true})
	if up, _ := c.analyzerReady.status(); !up {
		t.Fatal("empty replacement rule set did not mark the stream synced")
	}
}
