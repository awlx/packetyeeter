//go:build e2e

// This file drives a real haproxy binary (with the SPOE filter enabled)
// against PacketYeeter's actual collector-side SPOE agent implementation,
// using the same spoe-agent/spoe-message wiring documented in
// examples/packetyeeter.spoe.conf. It is gated behind the "e2e" build tag
// (run via `make e2e-test` or `go test -tags e2e ./...`) because it needs a
// working `haproxy` executable on PATH.
package spoe_test

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/dropmorepackets/haproxy-go/pkg/testutil"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/collector/haproxy/spoe"
)

// packetYeeterSPOEConfig mirrors examples/packetyeeter.spoe.conf, but the
// bracketed section name must stay "[e2e]" because that's what
// testutil.HAProxyConfig's frontend template references via
// "filter spoe engine e2e config ...".
const packetYeeterSPOEConfig = `
[e2e]
spoe-agent packet-yeeter-agent
    messages packet-yeeter-metrics
    option var-prefix packetyeeter
    option continue-on-error
    use-backend e2e-spoa
    timeout hello      1s
    timeout idle       2m
    timeout processing 1s
    log global

spoe-message packet-yeeter-metrics
    args src=src dst_port=var(txn.dst_port) method=var(txn.method) path=var(txn.path) host=var(txn.host) ua=var(txn.ua) has_cookies=var(txn.has_cookies)
    event on-http-response
    on-error ignore
    on-timeout ignore
`

func TestCollectorAgentReceivesSignalsFromRealHAProxy(t *testing.T) {
	if _, err := exec.LookPath("haproxy"); err != nil {
		t.Skip("haproxy binary not found on PATH, skipping e2e test")
	}

	var (
		mu      sync.Mutex
		signals []*apiv1.Signal
	)

	spoeAddr := fmt.Sprintf("127.0.0.1:%d", testutil.TCPPort(t))
	agent := spoe.NewCollectorAgent(spoeAddr, nil, spoe.CollectorCallbacks{
		EmitSignal: func(s *apiv1.Signal) {
			mu.Lock()
			defer mu.Unlock()
			signals = append(signals, s)
		},
	})
	if err := agent.Start(); err != nil {
		t.Fatalf("failed to start collector SPOE agent: %v", err)
	}
	t.Cleanup(agent.Stop)

	backend := "127.0.0.1:0"
	ln, err := net.Listen("tcp", backend)
	if err != nil {
		t.Fatalf("start fake backend listener: %v", err)
	}
	defer ln.Close()
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	cfg := testutil.HAProxyConfig{
		FrontendPort: fmt.Sprintf("%d", testutil.TCPPort(t)),
		EngineAddr:   spoeAddr,
		EngineConfig: packetYeeterSPOEConfig,
		BackendConfig: fmt.Sprintf(`
    server backend %s
`, ln.Addr().String()),
		CustomFrontendConfig: `
    http-request set-var(txn.dst_port) dst_port
    http-request set-var(txn.method) method
    http-request set-var(txn.path) path
    http-request set-var(txn.host) req.fhdr(host),field(1,::)
    http-request set-var(txn.ua) req.fhdr(user-agent),field(1,::)
    http-request set-var(txn.has_cookies) req.hdr_cnt(Cookie)
`,
	}
	cfg.Run(t)

	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+cfg.FrontendPort+"/e2e-path", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("User-Agent", "packetyeeter-e2e-test")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request to haproxy frontend failed: %v", err)
	}
	resp.Body.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := len(signals)
		mu.Unlock()
		if got > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(signals) == 0 {
		t.Fatal("timed out waiting for a signal to be emitted via real haproxy SPOE traffic")
	}

	sig := signals[0]
	if sig.Type != apiv1.SignalType_SIGNAL_HTTP_REQUEST {
		t.Fatalf("expected SIGNAL_HTTP_REQUEST, got %v", sig.Type)
	}
	http := sig.GetHttpContext()
	if http == nil {
		t.Fatal("expected HTTP context on signal")
	}
	if http.Method != "GET" {
		t.Errorf("expected method GET, got %q", http.Method)
	}
	if http.Path != "/e2e-path" {
		t.Errorf("expected path /e2e-path, got %q", http.Path)
	}
	if http.UserAgent != "packetyeeter-e2e-test" {
		t.Errorf("expected user-agent packetyeeter-e2e-test, got %q", http.UserAgent)
	}
}
