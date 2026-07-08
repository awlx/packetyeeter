package collector

import (
	"errors"
	"testing"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"

	"google.golang.org/grpc"
)

// fakeSignalStream is a minimal apiv1.AnalyzerService_StreamSignalsClient
// used to exercise sendSignalWithTimeout without a real gRPC connection.
type fakeSignalStream struct {
	grpc.ClientStream // embedded nil; only Send/Recv are exercised in tests

	sendFn func(*apiv1.Signal) error
}

func (f *fakeSignalStream) Send(s *apiv1.Signal) error {
	return f.sendFn(s)
}

func (f *fakeSignalStream) Recv() (*apiv1.Command, error) {
	return nil, errors.New("not implemented")
}

func TestSendSignalWithTimeout_ReturnsSendError(t *testing.T) {
	c := &Collector{}
	wantErr := errors.New("boom")
	stream := &fakeSignalStream{
		sendFn: func(*apiv1.Signal) error { return wantErr },
	}

	err := c.sendSignalWithTimeout(stream, &apiv1.Signal{}, time.Second)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped send error, got %v", err)
	}
}

func TestSendSignalWithTimeout_DetectsStuckSend(t *testing.T) {
	c := &Collector{}
	blockUntilTestEnds := make(chan struct{})
	t.Cleanup(func() { close(blockUntilTestEnds) })

	stream := &fakeSignalStream{
		sendFn: func(*apiv1.Signal) error {
			<-blockUntilTestEnds // never returns within the test timeout
			return nil
		},
	}

	start := time.Now()
	err := c.sendSignalWithTimeout(stream, &apiv1.Signal{}, 50*time.Millisecond)
	elapsed := time.Since(start)

	if !errors.Is(err, errSignalSendTimedOut) {
		t.Fatalf("expected errSignalSendTimedOut, got %v", err)
	}
	if elapsed > time.Second {
		t.Fatalf("sendSignalWithTimeout blocked for %v, want ~50ms", elapsed)
	}
}

func TestResetAnalyzerConnection_ClearsStreamAndConnectedState(t *testing.T) {
	c := &Collector{}
	c.connected.Store(true)
	// No real analyzerConn/signalStream set: resetAnalyzerConnection must
	// be safe to call even when they're nil (e.g. never connected yet).
	c.resetAnalyzerConnection()

	if c.connected.Load() {
		t.Fatal("expected connected to be false after reset")
	}
	if c.signalStream != nil {
		t.Fatal("expected signalStream to be nil after reset")
	}
	if c.analyzerConn != nil {
		t.Fatal("expected analyzerConn to be nil after reset")
	}
}
