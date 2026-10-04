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

type holdStreamAnalyzer struct {
	apiv1.UnimplementedAnalyzerServiceServer
}

func (holdStreamAnalyzer) StreamSignals(stream apiv1.AnalyzerService_StreamSignalsServer) error {
	<-stream.Context().Done()
	return nil
}

func TestManageAnalyzerConnectionTracksReadiness(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	apiv1.RegisterAnalyzerServiceServer(srv, holdStreamAnalyzer{})
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	c, err := New(Config{AnalyzerAddr: lis.Addr().String()}, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.wg.Add(1)
	go c.manageAnalyzerConnection()
	defer func() {
		c.cancel()
		c.wg.Wait()
		c.mu.Lock()
		if c.analyzerConn != nil {
			c.analyzerConn.Close()
		}
		c.mu.Unlock()
	}()

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
