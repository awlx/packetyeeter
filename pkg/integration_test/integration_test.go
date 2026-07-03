package integration_test

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/analyzer"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAnalyzerStreamSignalsAcceptsCollectorSignals(t *testing.T) {
	a := startTestAnalyzer(t)
	addr := a.Config.ListenAddr

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("create grpc client: %v", err)
	}
	defer conn.Close()

	client := apiv1.NewAnalyzerServiceClient(conn)
	stream, err := client.StreamSignals(ctx)
	if err != nil {
		t.Fatalf("open signal stream: %v", err)
	}

	ip := net.IPv4(192, 0, 2, 42)
	for i := 0; i < 5; i++ {
		if err := stream.Send(&apiv1.Signal{
			Id:        "integration-test-syn",
			Timestamp: timestamppb.Now(),
			Type:      apiv1.SignalType_SIGNAL_SYN_FLOOD,
			Source:    apiv1.SignalSource_SOURCE_EBPF,
			Ip:        ip.To4(),
			Weight:    100,
		}); err != nil {
			t.Fatalf("send signal: %v", err)
		}
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close signal stream: %v", err)
	}

	if _, err := stream.Recv(); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("receive stream close: %v", err)
	}

	eventually(t, 5*time.Second, func() bool {
		signalsByIP, _, _, _, _, _ := a.AIEngine.GetMetrics()
		byType, bySource := a.AIEngine.GetEntitySignalBreakdown(ip.String(), "ip")
		return signalsByIP[ip.String()] == 5 &&
			byType["syn_flood"] == 5 &&
			bySource["tcp"] == 5
	})
}

func startTestAnalyzer(t *testing.T) *analyzer.Analyzer {
	t.Helper()

	cfg := analyzer.Config{
		ListenAddr:                 reserveTCPAddr(t),
		MetricsAddr:                reserveTCPAddr(t),
		InspectorAddr:              "",
		JA4DBCachePath:             writeJA4Cache(t),
		StateDir:                   t.TempDir(),
		ReputationThreshold:        75.0,
		AIConfidenceThreshold:      0.1,
		AISuspiciousScoreThreshold: 0.1,
		AIBlockScoreThreshold:      0.2,
		AIWorkers:                  1,
		AIQueueSize:                100,
		DDoSIncompleteThreshold:    1,
		DDoSPatternThreshold:       1,
		DDoSTotalThreshold:         1,
		DDoSRequireHighFreq:        false,
		DryRun:                     true,
	}

	a, err := analyzer.New(cfg)
	if err != nil {
		t.Fatalf("create analyzer: %v", err)
	}
	if err := a.Start(); err != nil {
		t.Fatalf("start analyzer: %v", err)
	}
	t.Cleanup(a.Close)

	return a
}

func writeJA4Cache(t *testing.T) string {
	t.Helper()

	cachePath := filepath.Join(t.TempDir(), "ja4db.json")
	if err := os.WriteFile(cachePath, []byte(`[{"application":"integration-test","ja4_fingerprint":"test"}]`), 0644); err != nil {
		t.Fatalf("write JA4 cache: %v", err)
	}
	return cachePath
}

func reserveTCPAddr(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp address: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release tcp address: %v", err)
	}
	return addr
}

func eventually(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}
