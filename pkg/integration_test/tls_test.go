package integration_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/analyzer"
	"PacketYeeter/pkg/grpctls"
	"PacketYeeter/pkg/grpctls/grpctlstest"
)

func dialAnalyzer(t *testing.T, addr string, cfg grpctls.ClientConfig) apiv1.AnalyzerServiceClient {
	t.Helper()
	creds, err := grpctls.NewClientCredentials(cfg, logrus.StandardLogger())
	if err != nil {
		t.Fatalf("client credentials: %v", err)
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatalf("create grpc client: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return apiv1.NewAnalyzerServiceClient(conn)
}

func TestAnalyzerMutualTLS(t *testing.T) {
	dir := t.TempDir()
	ca := grpctlstest.NewCA(t, "packetyeeter-ca")
	other := grpctlstest.NewCA(t, "other-ca")
	caFile := ca.WriteCA(t, dir, "ca")
	serverCert, serverKey := ca.IssueServer(t, "analyzer", "127.0.0.1").Write(t, dir, "analyzer")
	collCert, collKey := ca.IssueClient(t, "collector-1", "collector-1").Write(t, dir, "collector")
	rogueCert, rogueKey := other.IssueClient(t, "rogue", "rogue").Write(t, dir, "rogue")

	a := startTestAnalyzer(t, func(cfg *analyzer.Config) {
		cfg.TLS = grpctls.ServerConfig{CertFile: serverCert, KeyFile: serverKey, ClientCAFile: caFile}
		cfg.ControlClientNames = []string{"controller"}
	})
	addr := a.Config.ListenAddr

	unary := func(client apiv1.AnalyzerServiceClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := client.GetReputation(ctx, &apiv1.ReputationRequest{Key: "192.0.2.1"})
		return err
	}

	for name, cfg := range map[string]grpctls.ClientConfig{
		"plaintext":          {},
		"no client cert":     {CAFile: caFile},
		"cert from other CA": {CAFile: caFile, CertFile: rogueCert, KeyFile: rogueKey},
	} {
		if err := unary(dialAnalyzer(t, addr, cfg)); status.Code(err) != codes.Unavailable {
			t.Fatalf("%s: GetReputation error = %v, want Unavailable", name, err)
		}
	}

	// Collectors are not in -control-client-names but keep the signal plane.
	client := dialAnalyzer(t, addr, grpctls.ClientConfig{CAFile: caFile, CertFile: collCert, KeyFile: collKey})
	if err := unary(client); err != nil {
		t.Fatalf("valid collector GetReputation: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := client.StreamSignals(ctx)
	if err != nil {
		t.Fatalf("open signal stream: %v", err)
	}
	ip := net.ParseIP("2001:db8::42")
	if err := stream.Send(&apiv1.Signal{
		Id:        "tls-test-syn",
		Timestamp: timestamppb.Now(),
		Type:      apiv1.SignalType_SIGNAL_SYN_FLOOD,
		Source:    apiv1.SignalSource_SOURCE_EBPF,
		Ip:        ip,
		Weight:    100,
	}); err != nil {
		t.Fatalf("send signal: %v", err)
	}
	eventually(t, 5*time.Second, func() bool {
		signalsByIP, _, _, _, _, _ := a.AIEngine.GetMetrics()
		return signalsByIP[ip.String()] == 1
	})
}

func TestAnalyzerRejectsInconsistentTLSConfig(t *testing.T) {
	_, err := analyzer.New(analyzer.Config{
		TLS: grpctls.ServerConfig{CertFile: "/nonexistent.crt", KeyFile: "/nonexistent.key"},
	})
	if err == nil {
		t.Fatal("analyzer.New accepted unreadable TLS files")
	}
	_, err = analyzer.New(analyzer.Config{ControlClientNames: []string{"controller"}})
	if err == nil {
		t.Fatal("analyzer.New accepted -control-client-names without -tls-client-ca")
	}
}

// Exercises the real PushRules handler, so a renamed RPC cannot silently
// escape -control-client-names.
func TestAnalyzerPushRulesControlClientNames(t *testing.T) {
	dir := t.TempDir()
	ca := grpctlstest.NewCA(t, "packetyeeter-ca")
	caFile := ca.WriteCA(t, dir, "ca")
	serverCert, serverKey := ca.IssueServer(t, "analyzer", "127.0.0.1").Write(t, dir, "analyzer")
	ctlCert, ctlKey := ca.IssueClient(t, "controller", "controller").Write(t, dir, "controller")
	collCert, collKey := ca.IssueClient(t, "collector-1", "collector-1").Write(t, dir, "collector")

	a := startTestAnalyzer(t, func(cfg *analyzer.Config) {
		cfg.TLS = grpctls.ServerConfig{CertFile: serverCert, KeyFile: serverKey, ClientCAFile: caFile}
		cfg.ControlClientNames = []string{"controller"}
		cfg.EnableRuleAPI = true
	})
	addr := a.Config.ListenAddr

	push := func(client apiv1.AnalyzerServiceClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, err := client.PushRules(ctx, &apiv1.RuleSet{Scope: "ctl", Rules: []*apiv1.Rule{dropRule("ntp", "192.0.2.10/32")}})
		return err
	}

	collector := dialAnalyzer(t, addr, grpctls.ClientConfig{CAFile: caFile, CertFile: collCert, KeyFile: collKey})
	if err := push(collector); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("collector PushRules error = %v, want PermissionDenied", err)
	}
	controller := dialAnalyzer(t, addr, grpctls.ClientConfig{CAFile: caFile, CertFile: ctlCert, KeyFile: ctlKey})
	if err := push(controller); err != nil {
		t.Fatalf("controller PushRules: %v", err)
	}
}

// Exercises the real WatchDecisions handler: the collector is denied the
// stream but can still feed it the fingerprint the controller receives.
func TestAnalyzerWatchDecisionsControlClientNames(t *testing.T) {
	dir := t.TempDir()
	ca := grpctlstest.NewCA(t, "packetyeeter-ca")
	caFile := ca.WriteCA(t, dir, "ca")
	serverCert, serverKey := ca.IssueServer(t, "analyzer", "127.0.0.1").Write(t, dir, "analyzer")
	ctlCert, ctlKey := ca.IssueClient(t, "controller", "controller").Write(t, dir, "controller")
	collCert, collKey := ca.IssueClient(t, "collector-1", "collector-1").Write(t, dir, "collector")

	a := startTestAnalyzer(t, func(cfg *analyzer.Config) {
		cfg.TLS = grpctls.ServerConfig{CertFile: serverCert, KeyFile: serverKey, ClientCAFile: caFile}
		cfg.ControlClientNames = []string{"controller"}
		cfg.EnableWatchAPI = true
	})
	addr := a.Config.ListenAddr
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collector := dialAnalyzer(t, addr, grpctls.ClientConfig{CAFile: caFile, CertFile: collCert, KeyFile: collKey})
	denied, err := collector.WatchDecisions(ctx, &apiv1.WatchRequest{Subscriber: "collector"})
	if err == nil {
		_, err = denied.Recv()
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("collector WatchDecisions error = %v, want PermissionDenied", err)
	}

	controller := dialAnalyzer(t, addr, grpctls.ClientConfig{CAFile: caFile, CertFile: ctlCert, KeyFile: ctlKey})
	watch, err := controller.WatchDecisions(ctx, &apiv1.WatchRequest{Subscriber: "controller"})
	if err != nil {
		t.Fatalf("controller WatchDecisions: %v", err)
	}
	received := make(chan error, 1)
	go func() {
		d, err := watch.Recv()
		if err == nil && d.GetFingerprint() == nil {
			err = status.Errorf(codes.Internal, "unexpected decision %v", d)
		}
		received <- err
	}()

	signals, err := collector.StreamSignals(ctx)
	if err != nil {
		t.Fatalf("open signal stream: %v", err)
	}
	fp := &apiv1.ScrubFingerprint{
		DstIp:           net.ParseIP("192.0.2.5").To4(),
		Protocol:        17,
		DstPort:         53,
		SrcNet:          net.ParseIP("198.51.100.0").To4(),
		Packets:         100,
		Bytes:           6400,
		IntervalSeconds: 10,
	}
	// The subscriber registers asynchronously, so resend until one arrives.
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := signals.Send(&apiv1.Signal{Type: apiv1.SignalType_SIGNAL_SCRUB_FINGERPRINT, Fingerprint: fp}); err != nil {
			t.Fatalf("send fingerprint: %v", err)
		}
		select {
		case err := <-received:
			if err != nil {
				t.Fatalf("controller watch: %v", err)
			}
			return
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("controller received no decision before timeout")
		}
	}
}
