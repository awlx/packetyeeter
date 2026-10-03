package collector

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/grpctls"
	"PacketYeeter/pkg/grpctls/grpctlstest"
)

// tlsStubAnalyzer records the verified client CN of each signal stream.
type tlsStubAnalyzer struct {
	apiv1.UnimplementedAnalyzerServiceServer
	clientCN chan string
}

func (s *tlsStubAnalyzer) StreamSignals(stream apiv1.AnalyzerService_StreamSignalsServer) error {
	cn := ""
	if p, ok := peer.FromContext(stream.Context()); ok {
		if info, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(info.State.VerifiedChains) > 0 {
			cn = info.State.VerifiedChains[0][0].Subject.CommonName
		}
	}
	s.clientCN <- cn
	<-stream.Context().Done()
	return nil
}

func startTLSStubAnalyzer(t *testing.T, cfg grpctls.ServerConfig) (string, chan string) {
	t.Helper()
	creds, err := grpctls.NewServerCredentials(cfg, logrus.New())
	if err != nil {
		t.Fatalf("server credentials: %v", err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	stub := &tlsStubAnalyzer{clientCN: make(chan string, 4)}
	srv := grpc.NewServer(grpc.Creds(creds))
	apiv1.RegisterAnalyzerServiceServer(srv, stub)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String(), stub.clientCN
}

func newTLSTestCollector(t *testing.T, addr string, tlsCfg grpctls.ClientConfig, timeout time.Duration) (*Collector, error) {
	t.Helper()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	c, err := New(Config{AnalyzerAddr: addr, AnalyzerTLS: tlsCfg}, logger)
	if err != nil {
		return nil, err
	}
	c.ctx, c.cancel = context.WithTimeout(context.Background(), timeout)
	t.Cleanup(func() {
		c.cancel()
		if c.analyzerConn != nil {
			c.analyzerConn.Close()
		}
	})
	return c, nil
}

func TestConnectToAnalyzerWithMutualTLS(t *testing.T) {
	dir := t.TempDir()
	ca := grpctlstest.NewCA(t, "ca")
	caFile := ca.WriteCA(t, dir, "ca")
	srvCert, srvKey := ca.IssueServer(t, "analyzer", "analyzer.internal").Write(t, dir, "analyzer")
	cliCert, cliKey := ca.IssueClient(t, "collector-1", "collector-1").Write(t, dir, "collector")
	addr, clientCN := startTLSStubAnalyzer(t, grpctls.ServerConfig{CertFile: srvCert, KeyFile: srvKey, ClientCAFile: caFile})

	c, err := newTLSTestCollector(t, addr, grpctls.ClientConfig{
		CAFile: caFile, CertFile: cliCert, KeyFile: cliKey, ServerName: "analyzer.internal",
	}, 10*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.connectToAnalyzer(); err != nil {
		t.Fatalf("connectToAnalyzer: %v", err)
	}
	select {
	case cn := <-clientCN:
		if cn != "collector-1" {
			t.Fatalf("analyzer saw client CN %q, want collector-1", cn)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("signal stream never reached the analyzer")
	}
}

func TestConnectToAnalyzerVerifiesServer(t *testing.T) {
	dir := t.TempDir()
	ca := grpctlstest.NewCA(t, "ca")
	other := grpctlstest.NewCA(t, "other")
	srvCert, srvKey := other.IssueServer(t, "impostor", "127.0.0.1").Write(t, dir, "impostor")
	addr, _ := startTLSStubAnalyzer(t, grpctls.ServerConfig{CertFile: srvCert, KeyFile: srvKey})

	c, err := newTLSTestCollector(t, addr, grpctls.ClientConfig{CAFile: ca.WriteCA(t, dir, "ca")}, time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.connectToAnalyzer(); err == nil {
		t.Fatal("connected to an analyzer whose certificate is not signed by -analyzer-tls-ca")
	}
}

func TestNewRejectsInconsistentAnalyzerTLS(t *testing.T) {
	_, err := New(Config{AnalyzerTLS: grpctls.ClientConfig{CertFile: "c.crt", KeyFile: "c.key"}}, logrus.New())
	if err == nil || !strings.Contains(err.Error(), "-analyzer-tls-ca") {
		t.Fatalf("cert without CA: error = %v", err)
	}
	_, err = New(Config{AnalyzerTLS: grpctls.ClientConfig{CAFile: "/nonexistent/ca.pem"}}, logrus.New())
	if err == nil || !strings.Contains(err.Error(), "/nonexistent/ca.pem") {
		t.Fatalf("unreadable CA: error = %v", err)
	}
}
