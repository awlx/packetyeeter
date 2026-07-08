//go:build e2e

// This file drives a real haproxy binary against the collector's HAProxy
// peer listener. It is gated behind the "e2e" build tag (run via
// `make e2e-test` or `go test -tags e2e ./...`) because it requires a
// working `haproxy` executable on PATH and is slower than the unit tests
// that run as part of the default `go test`/`make test` targets.
package haproxy_test

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/dropmorepackets/haproxy-go/pkg/testutil"
	"github.com/sirupsen/logrus"

	"PacketYeeter/pkg/collector/haproxy"
)

// fakeBlocker records BlockIP calls so the test can assert on them without
// requiring a loaded eBPF program/kernel maps, which are unavailable outside
// a privileged Linux host.
type fakeBlocker struct {
	mu      sync.Mutex
	blocked []string
}

func (f *fakeBlocker) BlockIP(ip net.IP, reason string, meta logrus.Fields) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blocked = append(f.blocked, ip.String())
	return nil
}

func (f *fakeBlocker) sawBlock(ip string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range f.blocked {
		if b == ip {
			return true
		}
	}
	return false
}

// TestPeerListenerReceivesUpdatesFromRealHAProxy starts a real haproxy
// process, has it track a stick-table entry for a client IP and mark it as
// abusive via the runtime API, and verifies the resulting peer-protocol
// update reaches PacketYeeter's collector-side peer listener and triggers a
// block decision.
func TestPeerListenerReceivesUpdatesFromRealHAProxy(t *testing.T) {
	if _, err := exec.LookPath("haproxy"); err != nil {
		t.Skip("haproxy binary not found on PATH, skipping e2e test")
	}

	blocker := &fakeBlocker{}
	port := testutil.TCPPort(t)

	srv := haproxy.NewServer(port, blocker)
	go srv.Start()

	cfg := testutil.HAProxyConfig{
		FrontendPort: fmt.Sprintf("%d", testutil.TCPPort(t)),
		CustomFrontendConfig: `
    http-request track-sc0 src table abusive_clients
    http-request sc-inc-gpc0(0)
`,
		CustomConfig: `
backend abusive_clients
    stick-table type ip size 1m expire 10m store gpc0 peers mypeers
`,
		PeerAddr: fmt.Sprintf("127.0.0.1:%d", port),
	}
	cfg.Run(t)

	// Drive traffic through the real haproxy frontend so it populates its
	// own stick-table and, because the table is bound to "peers mypeers",
	// syncs the update to our Go peer listener.
	client := &http.Client{Timeout: 5 * time.Second}
	for i := 0; i < 3; i++ {
		resp, err := client.Get("http://127.0.0.1:" + cfg.FrontendPort)
		if err != nil {
			t.Fatalf("request to haproxy frontend failed: %v", err)
		}
		resp.Body.Close()
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if blocker.sawBlock("127.0.0.1") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatal("timed out waiting for BlockIP to be called via real haproxy peer sync")
}
