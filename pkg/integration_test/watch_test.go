package integration_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/analyzer"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestWatchDecisionsReceivesCollectorFingerprint(t *testing.T) {
	a := startTestAnalyzer(t, func(cfg *analyzer.Config) { cfg.EnableWatchAPI = true })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(a.Config.ListenAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("create grpc client: %v", err)
	}
	defer conn.Close()
	client := apiv1.NewAnalyzerServiceClient(conn)

	watch, err := client.WatchDecisions(ctx, &apiv1.WatchRequest{Subscriber: "integration"})
	if err != nil {
		t.Fatalf("open watch stream: %v", err)
	}
	signals, err := client.StreamSignals(ctx)
	if err != nil {
		t.Fatalf("open signal stream: %v", err)
	}

	sent := &apiv1.ScrubFingerprint{
		CollectorId:     "spoofed",
		DstIp:           net.ParseIP("2001:db8::5").To16(),
		Protocol:        6,
		DstPort:         443,
		SizeBucket:      0,
		TtlBucket:       3,
		SrcNet:          net.ParseIP("2001:db8:1::").To16(),
		Dropped:         true,
		Packets:         4200,
		IntervalSeconds: 10,
		Bytes:           252000,
	}

	// The subscriber registers asynchronously, so keep sending until one
	// arrives rather than racing the first send.
	received := make(chan *apiv1.Decision, 1)
	recvErr := make(chan error, 1)
	go func() {
		d, err := watch.Recv()
		if err != nil {
			recvErr <- err
			return
		}
		received <- d
	}()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var got *apiv1.ScrubFingerprint
	for got == nil {
		if err := signals.Send(&apiv1.Signal{Type: apiv1.SignalType_SIGNAL_SCRUB_FINGERPRINT, Fingerprint: sent}); err != nil {
			t.Fatalf("send fingerprint: %v", err)
		}
		select {
		case d := <-received:
			got = d.GetFingerprint()
			if got == nil {
				t.Fatalf("expected a fingerprint decision, got %v", d)
			}
		case err := <-recvErr:
			t.Fatalf("watch recv: %v", err)
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("no fingerprint received before timeout")
		}
	}

	if !strings.HasPrefix(got.CollectorId, "127.0.0.1:") {
		t.Fatalf("collector_id = %q, want the analyzer's id for the stream", got.CollectorId)
	}
	want := proto.Clone(sent).(*apiv1.ScrubFingerprint)
	want.CollectorId = got.CollectorId
	if !proto.Equal(got, want) {
		t.Fatalf("fingerprint = %v, want %v", got, want)
	}
}

func TestWatchDecisionsDisabledByDefault(t *testing.T) {
	a := startTestAnalyzer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.NewClient(a.Config.ListenAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("create grpc client: %v", err)
	}
	defer conn.Close()

	watch, err := apiv1.NewAnalyzerServiceClient(conn).WatchDecisions(ctx, &apiv1.WatchRequest{})
	if err != nil {
		t.Fatalf("open watch stream: %v", err)
	}
	if _, err := watch.Recv(); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("recv err = %v, want PermissionDenied", err)
	}
}
