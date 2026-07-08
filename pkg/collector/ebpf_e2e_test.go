//go:build linux && e2e_ebpf

// This test loads and attaches the *real* eBPF/XDP program to a dummy
// network interface and exercises the full analyzer-command -> kernel-map
// enforcement path used in production. It has been validated locally on a
// real Linux host with root and BPF support; it cannot run on this
// project's default macOS development environment. It requires:
//
//   - Linux with BPF/XDP support in the running kernel
//   - root (or CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN)
//   - `ip` (iproute2) on PATH to create a scratch dummy interface
//   - the eBPF object built via `make bpf` before running this test
//
// Run it explicitly with:
//
//	sudo -E go test -tags e2e_ebpf -run TestKernelBlockEnforcement -v ./pkg/collector/...
//
// What it verifies: a Command{COMMAND_BLOCK_IP} received from the analyzer
// stream results in a real write to the kernel BlockedIPs map (via
// Collector.executeCommand -> Maps.BlockIP), and that the write is
// readable back out via Maps.ListBlockedIPs, proving the eBPF program
// loaded, attached, and its maps are wired correctly end-to-end.
//
// What it deliberately does NOT verify: that a real packet from the
// blocked source IP is actually dropped by the attached XDP program. That
// would additionally require spoofing traffic from the blocked source
// address (e.g. via a network namespace + veth pair) and is left as a
// follow-up; please treat this test as validating the map-write path only,
// not full packet-drop behavior.
package collector

import (
	"context"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	apiv1 "PacketYeeter/api/proto/v1"
)

const testDummyIface = "pytyeet0"

// stubAnalyzer is a minimal AnalyzerServiceServer that, as soon as a
// collector opens the signal stream, immediately pushes a single
// COMMAND_BLOCK_IP command back down the stream. It ignores whatever
// signals the collector sends.
type stubAnalyzer struct {
	apiv1.UnimplementedAnalyzerServiceServer
	blockIP net.IP
}

func (s *stubAnalyzer) StreamSignals(stream apiv1.AnalyzerService_StreamSignalsServer) error {
	if err := stream.Send(&apiv1.Command{
		Id:     "e2e-ebpf-block",
		Type:   apiv1.CommandType_COMMAND_BLOCK_IP,
		Ip:     s.blockIP.To4(),
		Reason: "e2e_ebpf test",
		Source: "e2e_ebpf_test",
	}); err != nil {
		return err
	}
	// Drain signals until the client disconnects.
	for {
		if _, err := stream.Recv(); err != nil {
			return nil
		}
	}
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root to load/attach eBPF programs")
	}
}

func requireIPCommand(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("iproute2 'ip' command not found on PATH")
	}
}

func setupDummyInterface(t *testing.T) {
	t.Helper()
	if out, err := exec.Command("ip", "link", "add", testDummyIface, "type", "dummy").CombinedOutput(); err != nil {
		t.Fatalf("failed to create dummy interface %s: %v: %s", testDummyIface, err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", testDummyIface).Run()
	})
	if out, err := exec.Command("ip", "link", "set", testDummyIface, "up").CombinedOutput(); err != nil {
		t.Fatalf("failed to bring up dummy interface %s: %v: %s", testDummyIface, err, out)
	}
}

func startStubAnalyzer(t *testing.T, blockIP net.IP) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for stub analyzer: %v", err)
	}
	srv := grpc.NewServer()
	apiv1.RegisterAnalyzerServiceServer(srv, &stubAnalyzer{blockIP: blockIP})
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)
	return l.Addr().String()
}

func TestKernelBlockEnforcement(t *testing.T) {
	requireRoot(t)
	requireIPCommand(t)
	setupDummyInterface(t)

	blockIP := net.ParseIP("203.0.113.42")
	analyzerAddr := startStubAnalyzer(t, blockIP)

	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	cfg := Config{
		Interface:       testDummyIface,
		AnalyzerAddr:    analyzerAddr,
		MetricsAddr:     "127.0.0.1:0",
		SPOEAddr:        "127.0.0.1:0",
		HAProxyPort:     0,
		SocketPath:      t.TempDir() + "/collector.sock",
		BlockDuration:   5 * time.Minute,
		PollInterval:    200 * time.Millisecond,
		SignalQueueSize: 100,
	}

	coll, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("collector.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := coll.Start(ctx); err != nil {
		t.Fatalf("collector.Start (requires a loaded eBPF program on a Linux kernel): %v", err)
	}
	defer coll.Stop()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		v4, _ := coll.Maps.ListBlockedIPs(cfg.BlockDuration)
		for _, entry := range v4 {
			if entry.IP == blockIP.String() {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for analyzer BLOCK command to be reflected in the kernel BlockedIPs map for %s", blockIP)
}
