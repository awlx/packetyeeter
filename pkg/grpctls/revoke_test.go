package grpctls_test

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"PacketYeeter/pkg/grpctls"
	"PacketYeeter/pkg/grpctls/grpctlstest"
)

const holdMethod = "/grpctls.test.Hold/Hold"

// holdService keeps a stream open until the client or the connection goes,
// like StreamSignals and WatchDecisions.
var holdService = grpc.ServiceDesc{
	ServiceName: "grpctls.test.Hold",
	HandlerType: (*any)(nil),
	Streams: []grpc.StreamDesc{{
		StreamName:    "Hold",
		ServerStreams: true,
		Handler: func(_ any, s grpc.ServerStream) error {
			if err := s.SendMsg(&emptypb.Empty{}); err != nil {
				return err
			}
			<-s.Context().Done()
			return nil
		},
	}},
}

func startHoldServer(t *testing.T, cfg grpctls.ServerConfig) (string, grpctls.ClientCAEnforcer) {
	t.Helper()
	creds, err := grpctls.NewServerCredentials(cfg, quietLog())
	if err != nil {
		t.Fatalf("server credentials: %v", err)
	}
	enforcer, ok := creds.(grpctls.ClientCAEnforcer)
	if !ok {
		t.Fatalf("mTLS credentials %T do not implement ClientCAEnforcer", creds)
	}
	srv := grpc.NewServer(grpc.Creds(creds))
	srv.RegisterService(&holdService, struct{}{})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String(), enforcer
}

// hold opens a held stream and returns a channel that receives its end.
func hold(t *testing.T, conn *grpc.ClientConn) <-chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, holdMethod)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if err := s.SendMsg(&emptypb.Empty{}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := s.CloseSend(); err != nil {
		t.Fatalf("close send: %v", err)
	}
	if err := s.RecvMsg(&emptypb.Empty{}); err != nil {
		t.Fatalf("stream not established: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- s.RecvMsg(&emptypb.Empty{}) }()
	return done
}

// Removing a CA from -tls-client-ca must cut the open streams of clients it
// signed (the documented way to revoke a compromised certificate), and only
// theirs.
func TestClientCARotationClosesUntrustedConnections(t *testing.T) {
	k := newPKI(t)
	clientCAFile := grpctlstest.WriteFile(t, filepath.Join(k.dir, "client-ca.pem"),
		append(append([]byte{}, k.ca.CertPEM...), k.otherCA.CertPEM...))
	addr, enforcer := startHoldServer(t, grpctls.ServerConfig{CertFile: k.serverCert, KeyFile: k.serverKy, ClientCAFile: clientCAFile})

	revoked := hold(t, dial(t, addr, k.client(t, k.ca, "compromised")))
	kept := hold(t, dial(t, addr, k.client(t, k.otherCA, "collector-new")))

	if n := enforcer.CloseUntrusted(); n != 0 {
		t.Fatalf("closed %d connections with an unchanged CA bundle", n)
	}
	grpctlstest.WriteFile(t, clientCAFile, k.otherCA.CertPEM)
	if n := enforcer.CloseUntrusted(); n != 1 {
		t.Fatalf("closed %d connections after removing a CA, want 1", n)
	}
	select {
	case err := <-revoked:
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("revoked stream ended with %v, want Unavailable", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream of a client the new CA bundle does not trust stayed open")
	}
	select {
	case err := <-kept:
		t.Fatalf("trusted client's stream ended: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if n := enforcer.CloseUntrusted(); n != 0 {
		t.Fatalf("second check closed %d more connections", n)
	}
}

func TestTLSWithoutClientCAHasNoEnforcer(t *testing.T) {
	k := newPKI(t)
	creds, err := grpctls.NewServerCredentials(grpctls.ServerConfig{CertFile: k.serverCert, KeyFile: k.serverKy}, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := creds.(grpctls.ClientCAEnforcer); ok {
		t.Fatal("TLS without client certificates has nothing to enforce")
	}
}
