package grpctls_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"PacketYeeter/pkg/grpctls"
	"PacketYeeter/pkg/grpctls/grpctlstest"
)

const (
	openMethod  = "/grpctls.test.Control/Open"
	pushMethod  = "/grpctls.test.Control/Push"
	watchMethod = "/grpctls.test.Control/Watch"
)

func unaryOK(fullMethod string) grpc.MethodDesc {
	name := fullMethod[strings.LastIndex(fullMethod, "/")+1:]
	return grpc.MethodDesc{MethodName: name, Handler: func(srv any, ctx context.Context, dec func(any) error, ic grpc.UnaryServerInterceptor) (any, error) {
		in := new(emptypb.Empty)
		if err := dec(in); err != nil {
			return nil, err
		}
		h := func(context.Context, any) (any, error) { return &emptypb.Empty{}, nil }
		if ic == nil {
			return h(ctx, in)
		}
		return ic(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: fullMethod}, h)
	}}
}

// A stand-in for the analyzer service: Open is open to any client, Push and
// Watch play the control-plane RPCs.
var testService = grpc.ServiceDesc{
	ServiceName: "grpctls.test.Control",
	HandlerType: (*any)(nil),
	Methods:     []grpc.MethodDesc{unaryOK(openMethod), unaryOK(pushMethod)},
	Streams: []grpc.StreamDesc{{
		StreamName:    "Watch",
		ServerStreams: true,
		Handler: func(_ any, s grpc.ServerStream) error {
			return s.SendMsg(&emptypb.Empty{})
		},
	}},
}

func quietLog() logrus.FieldLogger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

func startServer(t *testing.T, cfg grpctls.ServerConfig, controlNames []string) string {
	t.Helper()
	creds, err := grpctls.NewServerCredentials(cfg, quietLog())
	if err != nil {
		t.Fatalf("server credentials: %v", err)
	}
	var opts []grpc.ServerOption
	if creds != nil {
		opts = append(opts, grpc.Creds(creds))
	}
	if len(controlNames) > 0 {
		az := grpctls.NewMethodAuthorizer([]string{pushMethod, watchMethod}, controlNames, quietLog())
		opts = append(opts, grpc.ChainUnaryInterceptor(az.UnaryInterceptor()), grpc.ChainStreamInterceptor(az.StreamInterceptor()))
	}
	srv := grpc.NewServer(opts...)
	srv.RegisterService(&testService, struct{}{})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

func dial(t *testing.T, addr string, cfg grpctls.ClientConfig) *grpc.ClientConn {
	t.Helper()
	creds, err := grpctls.NewClientCredentials(cfg, quietLog())
	if err != nil {
		t.Fatalf("client credentials: %v", err)
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func call(conn *grpc.ClientConn, method string) (*peer.Peer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var p peer.Peer
	err := conn.Invoke(ctx, method, &emptypb.Empty{}, &emptypb.Empty{}, grpc.Peer(&p))
	return &p, err
}

func watch(conn *grpc.ClientConn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, watchMethod)
	if err != nil {
		return err
	}
	if err := s.SendMsg(&emptypb.Empty{}); err != nil {
		return err
	}
	if err := s.CloseSend(); err != nil {
		return err
	}
	return s.RecvMsg(&emptypb.Empty{})
}

func serverCN(t *testing.T, p *peer.Peer) string {
	t.Helper()
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.PeerCertificates) == 0 {
		t.Fatalf("peer auth info = %T, want TLS with a certificate", p.AuthInfo)
	}
	return info.State.PeerCertificates[0].Subject.CommonName
}

type pki struct {
	dir                  string
	ca, otherCA          *grpctlstest.CA
	caFile, otherCAFile  string
	serverCert, serverKy string
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	p := &pki{dir: t.TempDir(), ca: grpctlstest.NewCA(t, "test-ca"), otherCA: grpctlstest.NewCA(t, "other-ca")}
	p.caFile = p.ca.WriteCA(t, p.dir, "ca")
	p.otherCAFile = p.otherCA.WriteCA(t, p.dir, "other-ca")
	p.serverCert, p.serverKy = p.ca.IssueServer(t, "analyzer", "localhost", "127.0.0.1").Write(t, p.dir, "server")
	return p
}

func (p *pki) client(t *testing.T, ca *grpctlstest.CA, name string) grpctls.ClientConfig {
	t.Helper()
	cert, key := ca.IssueClient(t, name, name).Write(t, p.dir, name)
	return grpctls.ClientConfig{CAFile: p.caFile, CertFile: cert, KeyFile: key}
}

func wantCode(t *testing.T, err error, want codes.Code, what string) {
	t.Helper()
	if status.Code(err) != want {
		t.Fatalf("%s: got %v, want %v", what, err, want)
	}
}

func TestPlaintextWhenUnconfigured(t *testing.T) {
	addr := startServer(t, grpctls.ServerConfig{}, nil)
	conn := dial(t, addr, grpctls.ClientConfig{})
	p, err := call(conn, openMethod)
	if err != nil {
		t.Fatalf("plaintext call: %v", err)
	}
	if p.AuthInfo == nil || p.AuthInfo.AuthType() != "insecure" {
		t.Fatalf("plaintext peer auth info = %T, want insecure", p.AuthInfo)
	}
}

func TestTLSWithoutClientCA(t *testing.T) {
	k := newPKI(t)
	addr := startServer(t, grpctls.ServerConfig{CertFile: k.serverCert, KeyFile: k.serverKy}, nil)

	p, err := call(dial(t, addr, grpctls.ClientConfig{CAFile: k.caFile}), openMethod)
	if err != nil {
		t.Fatalf("TLS call without client cert: %v", err)
	}
	if cn := serverCN(t, p); cn != "analyzer" {
		t.Fatalf("server CN = %q, want analyzer", cn)
	}
	if info := p.AuthInfo.(credentials.TLSInfo); info.State.Version < tls.VersionTLS12 {
		t.Fatalf("negotiated TLS version %x, want >= 1.2", info.State.Version)
	}

	// The client verifies the server: a CA that did not sign it is refused.
	_, err = call(dial(t, addr, grpctls.ClientConfig{CAFile: k.otherCAFile}), openMethod)
	wantCode(t, err, codes.Unavailable, "client trusting another CA")

	// The server name must match a SAN.
	_, err = call(dial(t, addr, grpctls.ClientConfig{CAFile: k.caFile, ServerName: "wrong.example"}), openMethod)
	wantCode(t, err, codes.Unavailable, "mismatched server name")

	// A plaintext client cannot talk to a TLS listener.
	_, err = call(dial(t, addr, grpctls.ClientConfig{}), openMethod)
	wantCode(t, err, codes.Unavailable, "plaintext client on TLS listener")
}

func TestServerNameOverride(t *testing.T) {
	k := newPKI(t)
	cert, key := k.ca.IssueServer(t, "analyzer", "analyzer.internal").Write(t, k.dir, "named")
	addr := startServer(t, grpctls.ServerConfig{CertFile: cert, KeyFile: key}, nil)

	_, err := call(dial(t, addr, grpctls.ClientConfig{CAFile: k.caFile}), openMethod)
	wantCode(t, err, codes.Unavailable, "dial by IP without override")

	if _, err := call(dial(t, addr, grpctls.ClientConfig{CAFile: k.caFile, ServerName: "analyzer.internal"}), openMethod); err != nil {
		t.Fatalf("dial with -analyzer-tls-server-name: %v", err)
	}
}

func TestMutualTLS(t *testing.T) {
	k := newPKI(t)
	addr := startServer(t, grpctls.ServerConfig{CertFile: k.serverCert, KeyFile: k.serverKy, ClientCAFile: k.caFile}, nil)

	_, err := call(dial(t, addr, grpctls.ClientConfig{CAFile: k.caFile}), openMethod)
	wantCode(t, err, codes.Unavailable, "client without certificate")

	_, err = call(dial(t, addr, k.client(t, k.otherCA, "rogue")), openMethod)
	wantCode(t, err, codes.Unavailable, "client certificate from another CA")

	if _, err := call(dial(t, addr, k.client(t, k.ca, "collector-1")), openMethod); err != nil {
		t.Fatalf("valid client: %v", err)
	}
}

func TestControlClientNames(t *testing.T) {
	k := newPKI(t)
	addr := startServer(t, grpctls.ServerConfig{CertFile: k.serverCert, KeyFile: k.serverKy, ClientCAFile: k.caFile},
		[]string{"controller.example"})

	controller := dial(t, addr, k.client(t, k.ca, "controller.example"))
	collector := dial(t, addr, k.client(t, k.ca, "collector-1"))

	if _, err := call(controller, pushMethod); err != nil {
		t.Fatalf("named client unary control call: %v", err)
	}
	if err := watch(controller); err != nil {
		t.Fatalf("named client stream control call: %v", err)
	}
	_, err := call(collector, pushMethod)
	wantCode(t, err, codes.PermissionDenied, "other client unary control call")
	wantCode(t, watch(collector), codes.PermissionDenied, "other client stream control call")
	if _, err := call(collector, openMethod); err != nil {
		t.Fatalf("other client on a non-control method: %v", err)
	}
}

func TestControlClientNamesMatchCommonName(t *testing.T) {
	k := newPKI(t)
	addr := startServer(t, grpctls.ServerConfig{CertFile: k.serverCert, KeyFile: k.serverKy, ClientCAFile: k.caFile},
		[]string{"ctl"})
	cert, key := k.ca.IssueClient(t, "ctl").Write(t, k.dir, "cn-only")
	conn := dial(t, addr, grpctls.ClientConfig{CAFile: k.caFile, CertFile: cert, KeyFile: key})
	if _, err := call(conn, pushMethod); err != nil {
		t.Fatalf("CN match: %v", err)
	}
}

func TestAuthorizeRejectsUnverifiedPeers(t *testing.T) {
	az := grpctls.NewMethodAuthorizer([]string{pushMethod}, []string{"controller.example"}, quietLog())
	wantCode(t, az.Authorize(context.Background(), pushMethod), codes.PermissionDenied, "no peer")
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{}})
	wantCode(t, az.Authorize(ctx, pushMethod), codes.PermissionDenied, "plaintext peer")
	if err := az.Authorize(ctx, openMethod); err != nil {
		t.Fatalf("unrestricted method: %v", err)
	}
}

func TestRotation(t *testing.T) {
	k := newPKI(t)
	addr := startServer(t, grpctls.ServerConfig{CertFile: k.serverCert, KeyFile: k.serverKy, ClientCAFile: k.caFile}, nil)
	clientCfg := k.client(t, k.ca, "collector-1")

	p, err := call(dial(t, addr, clientCfg), openMethod)
	if err != nil {
		t.Fatalf("before rotation: %v", err)
	}
	if cn := serverCN(t, p); cn != "analyzer" {
		t.Fatalf("server CN = %q, want analyzer", cn)
	}

	rotated := k.ca.IssueServer(t, "analyzer-rotated", "localhost", "127.0.0.1")
	grpctlstest.WriteFile(t, k.serverCert, rotated.CertPEM)
	grpctlstest.WriteFile(t, k.serverKy, rotated.KeyPEM)

	p, err = call(dial(t, addr, clientCfg), openMethod)
	if err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if cn := serverCN(t, p); cn != "analyzer-rotated" {
		t.Fatalf("server CN after rotation = %q, want analyzer-rotated", cn)
	}

	// A broken rotation keeps serving the last good certificate.
	grpctlstest.WriteFile(t, k.serverCert, []byte("not a certificate"))
	p, err = call(dial(t, addr, clientCfg), openMethod)
	if err != nil {
		t.Fatalf("after broken rotation: %v", err)
	}
	if cn := serverCN(t, p); cn != "analyzer-rotated" {
		t.Fatalf("server CN after broken rotation = %q, want analyzer-rotated", cn)
	}
	if err := os.Remove(k.serverKy); err != nil {
		t.Fatal(err)
	}
	if _, err := call(dial(t, addr, clientCfg), openMethod); err != nil {
		t.Fatalf("after key file removed: %v", err)
	}
}

func TestClientCARotation(t *testing.T) {
	k := newPKI(t)
	clientCAFile := grpctlstest.WriteFile(t, filepath.Join(k.dir, "client-ca.pem"), k.ca.CertPEM)
	addr := startServer(t, grpctls.ServerConfig{CertFile: k.serverCert, KeyFile: k.serverKy, ClientCAFile: clientCAFile}, nil)

	newCAClient := k.client(t, k.otherCA, "collector-new")
	_, err := call(dial(t, addr, newCAClient), openMethod)
	wantCode(t, err, codes.Unavailable, "client from not-yet-trusted CA")

	grpctlstest.WriteFile(t, clientCAFile, append(append([]byte{}, k.ca.CertPEM...), k.otherCA.CertPEM...))
	if _, err := call(dial(t, addr, newCAClient), openMethod); err != nil {
		t.Fatalf("client from newly trusted CA: %v", err)
	}
}

func TestClientRotation(t *testing.T) {
	k := newPKI(t)
	addr := startServer(t, grpctls.ServerConfig{CertFile: k.serverCert, KeyFile: k.serverKy, ClientCAFile: k.caFile},
		[]string{"controller-v2"})
	cfg := k.client(t, k.ca, "controller-v1")
	creds, err := grpctls.NewClientCredentials(cfg, quietLog())
	if err != nil {
		t.Fatal(err)
	}

	dialCreds := func() *grpc.ClientConn {
		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	_, err = call(dialCreds(), pushMethod)
	wantCode(t, err, codes.PermissionDenied, "controller-v1")

	v2 := k.ca.IssueClient(t, "controller-v2", "controller-v2")
	grpctlstest.WriteFile(t, cfg.CertFile, v2.CertPEM)
	grpctlstest.WriteFile(t, cfg.KeyFile, v2.KeyPEM)
	if _, err := call(dialCreds(), pushMethod); err != nil {
		t.Fatalf("rotated client certificate: %v", err)
	}
}

func TestServerConfigValidation(t *testing.T) {
	k := newPKI(t)
	missing := filepath.Join(k.dir, "missing.pem")
	garbage := grpctlstest.WriteFile(t, filepath.Join(k.dir, "garbage.pem"), []byte("garbage"))
	cases := []struct {
		name string
		cfg  grpctls.ServerConfig
		want string
	}{
		{"cert without key", grpctls.ServerConfig{CertFile: k.serverCert}, "-tls-cert requires -tls-key"},
		{"key without cert", grpctls.ServerConfig{KeyFile: k.serverKy}, "-tls-key requires -tls-cert"},
		{"client CA without cert", grpctls.ServerConfig{ClientCAFile: k.caFile}, "-tls-client-ca requires"},
		{"unreadable cert", grpctls.ServerConfig{CertFile: missing, KeyFile: k.serverKy}, "missing.pem"},
		{"mismatched key", grpctls.ServerConfig{CertFile: k.serverCert, KeyFile: garbage}, "garbage.pem"},
		{"unreadable client CA", grpctls.ServerConfig{CertFile: k.serverCert, KeyFile: k.serverKy, ClientCAFile: missing}, "missing.pem"},
		{"client CA without PEM", grpctls.ServerConfig{CertFile: k.serverCert, KeyFile: k.serverKy, ClientCAFile: garbage}, "no PEM certificates"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := grpctls.NewServerCredentials(tc.cfg, quietLog())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
	if creds, err := grpctls.NewServerCredentials(grpctls.ServerConfig{}, quietLog()); creds != nil || err != nil {
		t.Fatalf("zero config = (%v, %v), want plaintext (nil, nil)", creds, err)
	}
}

func TestClientConfigValidation(t *testing.T) {
	k := newPKI(t)
	cl := k.client(t, k.ca, "collector-1")
	missing := filepath.Join(k.dir, "missing.pem")
	cases := []struct {
		name string
		cfg  grpctls.ClientConfig
		want string
	}{
		{"cert without key", grpctls.ClientConfig{CAFile: k.caFile, CertFile: cl.CertFile}, "-analyzer-tls-cert requires -analyzer-tls-key"},
		{"key without cert", grpctls.ClientConfig{CAFile: k.caFile, KeyFile: cl.KeyFile}, "-analyzer-tls-key requires -analyzer-tls-cert"},
		{"cert without CA", grpctls.ClientConfig{CertFile: cl.CertFile, KeyFile: cl.KeyFile}, "requires -analyzer-tls-ca"},
		{"server name without CA", grpctls.ClientConfig{ServerName: "a"}, "-analyzer-tls-server-name requires -analyzer-tls-ca"},
		{"unreadable CA", grpctls.ClientConfig{CAFile: missing}, "missing.pem"},
		{"unreadable cert", grpctls.ClientConfig{CAFile: k.caFile, CertFile: missing, KeyFile: cl.KeyFile}, "missing.pem"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := grpctls.NewClientCredentials(tc.cfg, quietLog())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
	creds, err := grpctls.NewClientCredentials(grpctls.ClientConfig{}, quietLog())
	if err != nil || creds.Info().SecurityProtocol != "insecure" {
		t.Fatalf("zero config = (%v, %v), want insecure credentials", creds, err)
	}
}

func TestParseNames(t *testing.T) {
	got := grpctls.ParseNames(" a.example, ,b ,")
	if len(got) != 2 || got[0] != "a.example" || got[1] != "b" {
		t.Fatalf("ParseNames = %q", got)
	}
}
