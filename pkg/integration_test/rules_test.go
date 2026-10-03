package integration_test

import (
	"context"
	"slices"
	"testing"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/analyzer"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func startRuleAnalyzer(t *testing.T, enableRuleAPI bool) *analyzer.Analyzer {
	t.Helper()
	a, err := analyzer.New(analyzer.Config{
		ListenAddr:     reserveTCPAddr(t),
		MetricsAddr:    reserveTCPAddr(t),
		JA4DBCachePath: writeJA4Cache(t),
		StateDir:       t.TempDir(),
		AIWorkers:      1,
		AIQueueSize:    100,
		EnableRuleAPI:  enableRuleAPI,
	})
	if err != nil {
		t.Fatalf("create analyzer: %v", err)
	}
	if err := a.Start(); err != nil {
		t.Fatalf("start analyzer: %v", err)
	}
	t.Cleanup(a.Close)
	return a
}

func dropRule(id, dst string) *apiv1.Rule {
	return &apiv1.Rule{
		Id:        id,
		DstPrefix: dst,
		Protocols: []uint32{17},
		SrcPorts:  []*apiv1.PortRange{{From: 123, To: 123}},
		Action:    apiv1.RuleAction_RULE_ACTION_DROP,
		ExpiresAt: timestamppb.New(time.Now().Add(10 * time.Minute)),
	}
}

// connectScrubCollector opens a signal stream and announces scrub mode, as a
// scrub collector does on every (re)connect.
func connectScrubCollector(t *testing.T, ctx context.Context, client apiv1.AnalyzerServiceClient) apiv1.AnalyzerService_StreamSignalsClient {
	t.Helper()
	stream, err := client.StreamSignals(ctx)
	if err != nil {
		t.Fatalf("open signal stream: %v", err)
	}
	if err := stream.Send(&apiv1.Signal{
		Id:       "collector-role",
		Type:     apiv1.SignalType_SIGNAL_UNKNOWN,
		Metadata: map[string]string{"role": "scrub", "node": "scrub-test"},
	}); err != nil {
		t.Fatalf("send role: %v", err)
	}
	return stream
}

func recvRules(t *testing.T, stream apiv1.AnalyzerService_StreamSignalsClient) *apiv1.RuleSetDelta {
	t.Helper()
	for {
		cmd, err := stream.Recv()
		if err != nil {
			t.Fatalf("receive command: %v", err)
		}
		if cmd.GetType() == apiv1.CommandType_COMMAND_SET_RULES {
			return cmd.GetRules()
		}
	}
}

func upsertIDs(d *apiv1.RuleSetDelta) []string {
	var ids []string
	for _, r := range d.GetUpsert() {
		ids = append(ids, r.GetId())
	}
	slices.Sort(ids)
	return ids
}

func TestPushRulesReachesScrubCollectorOverGRPC(t *testing.T) {
	a := startRuleAnalyzer(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(a.Config.ListenAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("create grpc client: %v", err)
	}
	defer conn.Close()
	client := apiv1.NewAnalyzerServiceClient(conn)

	stream := connectScrubCollector(t, ctx, client)
	if first := recvRules(t, stream); !first.GetReplace() || len(first.GetUpsert()) != 0 {
		t.Fatalf("first delta = %v, want an empty replace", first)
	}

	ack, err := client.PushRules(ctx, &apiv1.RuleSet{Scope: "ctl", Rules: []*apiv1.Rule{dropRule("ntp", "192.0.2.10/32")}})
	if err != nil {
		t.Fatalf("PushRules: %v", err)
	}
	if ack.GetCollectors() != 1 {
		t.Errorf("ack.collectors = %d, want 1", ack.GetCollectors())
	}
	if d := recvRules(t, stream); !d.GetReplace() || !slices.Equal(upsertIDs(d), []string{"ctl/ntp"}) {
		t.Fatalf("delta = %v, want the full set (ctl/ntp) as a replacement", d)
	}

	// A reconnecting scrub collector gets the full set as a replace.
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close first stream: %v", err)
	}
	again := connectScrubCollector(t, ctx, client)
	if d := recvRules(t, again); !d.GetReplace() || !slices.Equal(upsertIDs(d), []string{"ctl/ntp"}) {
		t.Fatalf("reconnect delta = %v, want replace with ctl/ntp", d)
	}

	if _, err := client.PushRules(ctx, &apiv1.RuleSet{Scope: "ctl"}); err != nil {
		t.Fatalf("PushRules(empty): %v", err)
	}
	if d := recvRules(t, again); !d.GetReplace() || len(d.GetUpsert()) != 0 {
		t.Fatalf("delta = %v, want an empty replacement", d)
	}
}

func TestPushRulesDisabledByDefault(t *testing.T) {
	a := startRuleAnalyzer(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(a.Config.ListenAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("create grpc client: %v", err)
	}
	defer conn.Close()

	_, err = apiv1.NewAnalyzerServiceClient(conn).PushRules(ctx, &apiv1.RuleSet{Scope: "ctl", Rules: []*apiv1.Rule{dropRule("ntp", "192.0.2.10/32")}})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("PushRules without -enable-rule-api: %v, want PermissionDenied", err)
	}
}
