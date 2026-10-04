package analyzer

import (
	"context"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"PacketYeeter/pkg/grpctls"
	"PacketYeeter/pkg/grpctls/grpctlstest"
)

func TestNewRejectsControlClientNamesWithoutClientCA(t *testing.T) {
	dir := t.TempDir()
	ca := grpctlstest.NewCA(t, "ca")
	cert, key := ca.IssueServer(t, "analyzer", "localhost").Write(t, dir, "analyzer")
	for name, tlsCfg := range map[string]grpctls.ServerConfig{
		"plaintext":       {},
		"server TLS only": {CertFile: cert, KeyFile: key},
	} {
		_, err := New(Config{TLS: tlsCfg, ControlClientNames: []string{"controller"}})
		if err == nil || !strings.Contains(err.Error(), "-control-client-names requires -tls-client-ca") {
			t.Fatalf("%s: error = %v", name, err)
		}
	}
}

func TestNewRejectsScrubClientNamesWithoutClientCA(t *testing.T) {
	dir := t.TempDir()
	ca := grpctlstest.NewCA(t, "ca")
	cert, key := ca.IssueServer(t, "analyzer", "localhost").Write(t, dir, "analyzer")
	for name, tlsCfg := range map[string]grpctls.ServerConfig{
		"plaintext":       {},
		"server TLS only": {CertFile: cert, KeyFile: key},
	} {
		_, err := New(Config{TLS: tlsCfg, ScrubClientNames: []string{"scrub-a"}})
		if err == nil || !strings.Contains(err.Error(), "-scrub-client-names requires -tls-client-ca") {
			t.Fatalf("%s: error = %v", name, err)
		}
	}
	a, err := New(Config{
		TLS:              grpctls.ServerConfig{CertFile: cert, KeyFile: key, ClientCAFile: ca.WriteCA(t, dir, "ca")},
		ScrubClientNames: []string{"scrub-a"},
	})
	if err != nil {
		t.Fatalf("with mTLS: %v", err)
	}
	if a.ScrubRateLimiter == nil {
		t.Fatal("trusted-only limiter not created with -scrub-client-names")
	}
	a.Close()

	plain, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if plain.ScrubRateLimiter != nil {
		t.Fatal("trusted-only limiter created without -scrub-client-names")
	}
}

func TestNewRejectsBadTLSFlags(t *testing.T) {
	if _, err := New(Config{TLS: grpctls.ServerConfig{CertFile: "x.crt"}}); err == nil || !strings.Contains(err.Error(), "-tls-key") {
		t.Fatalf("cert without key: error = %v", err)
	}
}

func TestControlMethodsAreGated(t *testing.T) {
	dir := t.TempDir()
	ca := grpctlstest.NewCA(t, "ca")
	cert, key := ca.IssueServer(t, "analyzer", "localhost").Write(t, dir, "analyzer")
	a, err := New(Config{
		TLS:                grpctls.ServerConfig{CertFile: cert, KeyFile: key, ClientCAFile: ca.WriteCA(t, dir, "ca")},
		ControlClientNames: []string{"controller"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.grpcCreds == nil || a.controlAuthz == nil {
		t.Fatal("TLS credentials or control authorizer not configured")
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{}})
	for _, m := range ControlMethods {
		if code := status.Code(a.controlAuthz.Authorize(ctx, m)); code != codes.PermissionDenied {
			t.Fatalf("%s without verified certificate: code %v, want PermissionDenied", m, code)
		}
	}
	if err := a.controlAuthz.Authorize(ctx, "/packetyeeter.v1.AnalyzerService/StreamSignals"); err != nil {
		t.Fatalf("StreamSignals must stay open to any authenticated client: %v", err)
	}
}

func TestPlaintextByDefault(t *testing.T) {
	a, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.grpcCreds != nil || a.controlAuthz != nil {
		t.Fatal("zero config must keep the plaintext listener without authorization")
	}
}
