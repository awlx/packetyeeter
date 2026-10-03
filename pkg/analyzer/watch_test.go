package analyzer

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/analyzer/aidetection"
	"PacketYeeter/pkg/analyzer/reputation"
	"PacketYeeter/pkg/metrics"
)

// fakeWatchStream is a WatchDecisions server stream. When gate is non-nil,
// each Send waits for a token, which models a slow controller.
type fakeWatchStream struct {
	grpc.ServerStream
	ctx  context.Context
	got  chan *apiv1.Decision
	gate chan struct{}
}

func (f *fakeWatchStream) Context() context.Context { return f.ctx }

func (f *fakeWatchStream) Send(d *apiv1.Decision) error {
	if f.gate != nil {
		select {
		case <-f.gate:
		case <-f.ctx.Done():
			return f.ctx.Err()
		}
	}
	select {
	case f.got <- d:
		return nil
	case <-f.ctx.Done():
		return f.ctx.Err()
	}
}

type watchClient struct {
	stream *fakeWatchStream
	cancel context.CancelFunc
	done   chan error
}

func (w *watchClient) next(t *testing.T) *apiv1.Decision {
	t.Helper()
	select {
	case d := <-w.stream.got:
		return d
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a decision")
		return nil
	}
}

func (w *watchClient) expectNone(t *testing.T) {
	t.Helper()
	select {
	case d := <-w.stream.got:
		t.Fatalf("unexpected decision: %v", d)
	case <-time.After(100 * time.Millisecond):
	}
}

func (w *watchClient) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-w.done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("WatchDecisions handler did not return")
		return nil
	}
}

func newWatchAnalyzer(t *testing.T, cfg Config) *Analyzer {
	t.Helper()
	cfg.EnableWatchAPI = true
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.cancel)
	rep := reputation.New(time.Hour, 0.95, 100)
	t.Cleanup(rep.Stop)
	a.Reputation = rep
	a.ReputationHelper = NewReputationHelper(rep)
	return a
}

// startWatch runs the handler and returns once the subscriber is registered,
// so later publishes are guaranteed to reach it.
func startWatch(t *testing.T, a *Analyzer, name string, gate chan struct{}, buf int) *watchClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	w := &watchClient{
		stream: &fakeWatchStream{ctx: ctx, got: make(chan *apiv1.Decision, buf), gate: gate},
		cancel: cancel,
		done:   make(chan error, 1),
	}
	before := a.watch.active.Load()
	go func() { w.done <- a.WatchDecisions(&apiv1.WatchRequest{Subscriber: name}, w.stream) }()
	deadline := time.Now().Add(2 * time.Second)
	for a.watch.active.Load() == before {
		select {
		case err := <-w.done:
			w.done <- err
			return w
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("subscriber never registered")
		}
		time.Sleep(time.Millisecond)
	}
	return w
}

func blockCmd(ip string) *apiv1.Command {
	return &apiv1.Command{Type: apiv1.CommandType_COMMAND_BLOCK_IP, Ip: net.ParseIP(ip).To4(), Reason: "test"}
}

func registerFakeCollectors(t *testing.T, a *Analyzer, n int) []*fakeCollectorStream {
	t.Helper()
	streams := make([]*fakeCollectorStream, n)
	for i := range streams {
		streams[i] = newFakeCollectorStream()
		if id := a.registerCollector(context.Background(), &collectorStream{stream: streams[i]}); id == "" {
			t.Fatal("registerCollector refused a collector")
		}
	}
	return streams
}

func TestWatchDecisionsDisabledIsPermissionDenied(t *testing.T) {
	a := newTestAnalyzer(t)
	err := a.WatchDecisions(&apiv1.WatchRequest{}, &fakeWatchStream{ctx: context.Background()})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
	// Publishing with the API off must be a no-op, not a panic.
	a.publishCommand(blockCmd("192.0.2.1"))
	a.publishCampaign(aidetection.CampaignDetection{})
}

func TestWatchDecisionsSubscriberLimit(t *testing.T) {
	a := newWatchAnalyzer(t, Config{WatchMaxSubscribers: 2})
	first := startWatch(t, a, "one", nil, 8)
	startWatch(t, a, "two", nil, 8)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := a.WatchDecisions(&apiv1.WatchRequest{Subscriber: "three"}, &fakeWatchStream{ctx: ctx})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("err = %v, want ResourceExhausted", err)
	}

	first.cancel()
	if err := first.wait(t); status.Code(err) != codes.Canceled {
		t.Fatalf("handler returned %v, want Canceled", err)
	}
	if w := startWatch(t, a, "three", nil, 8); a.watch.active.Load() != 2 {
		t.Fatalf("freed slot not reusable: active=%d", a.watch.active.Load())
	} else {
		w.cancel()
	}
}

// Broadcast fans one decision out to every collector; the stream must carry it
// once. BLOCK_CIDR is never issued by the analyzer today, so BLOCK_IP stands
// in for the spec's acceptance check.
func TestWatchDecisionsPublishesEachCommandOnce(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})
	collectors := registerFakeCollectors(t, a, 3)
	w := startWatch(t, a, "controller", nil, 16)

	cmd := blockCmd("192.0.2.10")
	a.Broadcast(cmd)
	for _, c := range collectors {
		c.waitForCommand(t)
	}
	d := w.next(t)
	if got := d.GetCommand(); got != cmd {
		t.Fatalf("decision = %v, want the broadcast command", d)
	}
	w.expectNone(t)

	// Deduplicated repeat: not sent, so not published.
	a.Broadcast(blockCmd("192.0.2.10"))
	w.expectNone(t)

	single := blockCmd("192.0.2.11")
	a.sendCommand(&collectorStream{stream: collectors[0]}, single)
	collectors[0].waitForCommand(t)
	if got := w.next(t).GetCommand(); got != single {
		t.Fatalf("sendCommand decision = %v, want %v", got, single)
	}
	w.expectNone(t)
}

// Suppressed commands are not published: the stream reflects enforcement.
func TestWatchDecisionsSkipsSuppressedCommands(t *testing.T) {
	t.Run("dry-run", func(t *testing.T) {
		a := newWatchAnalyzer(t, Config{DryRun: true})
		collectors := registerFakeCollectors(t, a, 2)
		w := startWatch(t, a, "controller", nil, 16)

		a.Broadcast(blockCmd("192.0.2.20"))
		a.sendCommand(&collectorStream{stream: collectors[0]}, blockCmd("192.0.2.21"))
		w.expectNone(t)
	})

	t.Run("kill switch", func(t *testing.T) {
		a := newWatchAnalyzer(t, Config{})
		registerFakeCollectors(t, a, 2)
		w := startWatch(t, a, "controller", nil, 16)
		a.StopEnforcement("test")

		a.Broadcast(blockCmd("192.0.2.30"))
		w.expectNone(t)

		unblock := &apiv1.Command{Type: apiv1.CommandType_COMMAND_UNBLOCK_IP, Ip: net.ParseIP("192.0.2.30").To4()}
		a.Broadcast(unblock)
		if got := w.next(t).GetCommand(); got != unblock {
			t.Fatalf("relieving command not published, got %v", got)
		}
	})
}

// Drives the real campaign aggregator, then the engine hook's target.
func TestWatchDecisionsPublishesCampaignObservation(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})
	w := startWatch(t, a, "controller", nil, 16)

	agg := aidetection.NewCampaignAggregator(aidetection.CampaignConfig{
		Window: time.Minute, Retention: 2 * time.Minute, MinSignals: 4, MinDestIPs: 4,
		MinDestSubnets: 3, MinDestPorts: 4, MinWeakSourceIPs: 4, WeakSourceMaxWeight: 2, WeakSignalMaxWeight: 1.5,
	})
	now := time.Date(2026, 7, 3, 9, 0, 0, 0, time.UTC)
	for i := 1; i <= 4; i++ {
		agg.Record(aidetection.Signal{
			Type:      aidetection.SignalUDPFlood,
			Source:    aidetection.SourceUDP,
			IP:        net.ParseIP(fmt.Sprintf("198.51.100.%d", i)),
			Weight:    1,
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Metadata: map[string]interface{}{
				"dest_ip":      fmt.Sprintf("203.0.113.%d", i),
				"dst_port":     uint32(53),
				"collector_id": "collector-a",
			},
		})
	}
	detections := agg.Evaluate(now.Add(5 * time.Second))
	if len(detections) != 1 {
		t.Fatalf("expected one campaign detection, got %d", len(detections))
	}
	a.publishCampaign(detections[0])

	obs := w.next(t).GetCampaign()
	if obs == nil {
		t.Fatal("expected a campaign observation")
	}
	if obs.Vector != string(detections[0].Vector) || obs.Protocol != 17 || obs.DstPortBucket != "53" ||
		obs.DstPrefix != "203.0.113.0/24" || obs.RatePps <= 0 || !obs.ObservedAt.AsTime().Equal(detections[0].LastSeen) {
		t.Fatalf("unexpected observation: %v", obs)
	}
}

func TestCampaignObservationLeavesUnknownFieldsEmpty(t *testing.T) {
	obs := campaignObservation(aidetection.CampaignDetection{
		Vector: aidetection.SignalUDPFlood,
		Key:    "vector=udp_flood|source=udp|collector=any|dest_subnet=any",
	})
	if obs.Protocol != 0 || obs.DstPortBucket != "" || obs.DstPrefix != "" || obs.ObservedAt != nil {
		t.Fatalf("unknown fields must stay empty: %v", obs)
	}
}

// fakeSignalStream feeds signals into StreamSignals and then ends the stream.
type fakeSignalStream struct {
	apiv1.AnalyzerService_StreamSignalsServer
	ctx     context.Context
	signals []*apiv1.Signal
}

func (f *fakeSignalStream) Context() context.Context { return f.ctx }

func (f *fakeSignalStream) Recv() (*apiv1.Signal, error) {
	if len(f.signals) == 0 {
		return nil, io.EOF
	}
	s := f.signals[0]
	f.signals = f.signals[1:]
	return s, nil
}

func (f *fakeSignalStream) Send(*apiv1.Command) error { return nil }

func validFingerprint() *apiv1.ScrubFingerprint {
	return &apiv1.ScrubFingerprint{
		CollectorId:     "spoofed",
		DstIp:           net.ParseIP("203.0.113.5").To4(),
		Protocol:        17,
		DstPort:         53,
		SizeBucket:      4,
		TtlBucket:       1,
		SrcNet:          net.ParseIP("198.51.100.0").To4(),
		Packets:         1000,
		IntervalSeconds: 10,
		Bytes:           1500000,
	}
}

func TestFingerprintSignalsArePublishedNotScored(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})
	w := startWatch(t, a, "controller", nil, 16)
	srcIP := net.ParseIP("192.0.2.50").To4()

	invalid := []*apiv1.ScrubFingerprint{
		nil,
		{DstIp: []byte{1, 2, 3}, SrcNet: []byte{1, 2, 3}, IntervalSeconds: 10},
		func() *apiv1.ScrubFingerprint {
			f := validFingerprint()
			f.SrcNet = net.ParseIP("2001:db8::").To16()
			return f
		}(),
		func() *apiv1.ScrubFingerprint { f := validFingerprint(); f.TtlBucket = 8; return f }(),
		func() *apiv1.ScrubFingerprint { f := validFingerprint(); f.SizeBucket = 5; return f }(),
		func() *apiv1.ScrubFingerprint { f := validFingerprint(); f.DstPort = 70000; return f }(),
		func() *apiv1.ScrubFingerprint { f := validFingerprint(); f.IntervalSeconds = 0; return f }(),
	}
	v6 := validFingerprint()
	v6.DstIp = net.ParseIP("2001:db8::5").To16()
	v6.SrcNet = net.ParseIP("2001:db8::").To16()

	signals := make([]*apiv1.Signal, 0, len(invalid)+2)
	for _, fp := range invalid {
		signals = append(signals, &apiv1.Signal{Type: apiv1.SignalType_SIGNAL_SCRUB_FINGERPRINT, Fingerprint: fp})
	}
	// A populated ip and weight must still never reach scoring.
	signals = append(signals,
		&apiv1.Signal{Type: apiv1.SignalType_SIGNAL_SCRUB_FINGERPRINT, Ip: srcIP, Weight: 100, Fingerprint: validFingerprint()},
		&apiv1.Signal{Type: apiv1.SignalType_SIGNAL_SCRUB_FINGERPRINT, Fingerprint: v6},
	)

	invalidBefore := testutil.ToFloat64(metrics.WatchInvalidFingerprintsTotal)
	publishedBefore := testutil.ToFloat64(metrics.WatchPublishedTotal.WithLabelValues(watchKindFingerprint))
	if err := a.StreamSignals(&fakeSignalStream{ctx: context.Background(), signals: signals}); err != nil {
		t.Fatalf("StreamSignals: %v", err)
	}

	for _, want := range []int{4, 16} {
		fp := w.next(t).GetFingerprint()
		if fp == nil || len(fp.DstIp) != want {
			t.Fatalf("expected a %d-byte fingerprint, got %v", want, fp)
		}
		if fp.CollectorId == "spoofed" || !strings.HasPrefix(fp.CollectorId, "unknown#") {
			t.Fatalf("collector_id = %q, want the analyzer's stream id", fp.CollectorId)
		}
	}
	w.expectNone(t)

	if got := testutil.ToFloat64(metrics.WatchInvalidFingerprintsTotal) - invalidBefore; got != float64(len(invalid)) {
		t.Fatalf("invalid fingerprints counted = %v, want %d", got, len(invalid))
	}
	if got := testutil.ToFloat64(metrics.WatchPublishedTotal.WithLabelValues(watchKindFingerprint)) - publishedBefore; got != 2 {
		t.Fatalf("published fingerprints = %v, want 2", got)
	}
	if score := a.Reputation.GetScore(srcIP.String(), reputation.TypeIP); score != 0 {
		t.Fatalf("fingerprint changed reputation: %v", score)
	}
	if a.wasRecentlyBlocked(srcIP) {
		t.Fatal("fingerprint led to a block")
	}
	a.httpRateMu.Lock()
	tracked := len(a.httpRateByIP)
	a.httpRateMu.Unlock()
	if tracked != 0 {
		t.Fatalf("fingerprint reached per-IP tracking: %d entries", tracked)
	}
}

// Fingerprints are never scored even with the watch API off.
func TestFingerprintSignalsIgnoredWhenWatchDisabled(t *testing.T) {
	a := newTestAnalyzer(t)
	srcIP := net.ParseIP("192.0.2.51").To4()
	sig := &apiv1.Signal{Type: apiv1.SignalType_SIGNAL_SCRUB_FINGERPRINT, Ip: srcIP, Weight: 100, Fingerprint: validFingerprint()}
	if err := a.StreamSignals(&fakeSignalStream{ctx: context.Background(), signals: []*apiv1.Signal{sig}}); err != nil {
		t.Fatalf("StreamSignals: %v", err)
	}
	if score := a.Reputation.GetScore(srcIP.String(), reputation.TypeIP); score != 0 {
		t.Fatalf("fingerprint changed reputation: %v", score)
	}
}

func TestWatchSlowSubscriberDropsOldest(t *testing.T) {
	const bufSize, total = 4, 50
	a := newWatchAnalyzer(t, Config{WatchBufferSize: bufSize})
	gate := make(chan struct{})
	slow := startWatch(t, a, "slow", gate, total)
	fast := startWatch(t, a, "fast", nil, total)

	droppedBefore := testutil.ToFloat64(metrics.WatchDroppedTotal)
	cmds := make([]*apiv1.Command, total)
	for i := range cmds {
		cmds[i] = blockCmd(fmt.Sprintf("192.0.2.%d", i+1))
	}
	// Publish in lockstep with the fast subscriber so its own small ring
	// never overflows; the slow one is stuck in Send the whole time.
	ack := make(chan struct{})
	published := make(chan struct{})
	go func() {
		defer close(published)
		for _, cmd := range cmds {
			a.publishCommand(cmd)
			<-ack
		}
	}()
	for i := 0; i < total; i++ {
		if got := fast.next(t).GetCommand(); got != cmds[i] {
			t.Fatalf("fast subscriber decision %d out of order", i)
		}
		ack <- struct{}{}
	}
	select {
	case <-published:
	case <-time.After(2 * time.Second):
		t.Fatal("publishing blocked on a slow subscriber")
	}

	// The slow sender holds at most one decision in flight outside its ring.
	slowSub := slowSubscriber(t, a, "slow")
	dropped := slowSub.droppedCount()
	if dropped < total-bufSize-1 {
		t.Fatalf("dropped = %d, want at least %d", dropped, total-bufSize-1)
	}
	if got := testutil.ToFloat64(metrics.WatchDroppedTotal) - droppedBefore; got != float64(dropped) {
		t.Fatalf("dropped metric delta = %v, want %d", got, dropped)
	}

	close(gate)
	delivered := total - int(dropped)
	var last *apiv1.Command
	for i := 0; i < delivered; i++ {
		last = slow.next(t).GetCommand()
	}
	if last != cmds[total-1] {
		t.Fatal("slow subscriber did not end on the newest decision")
	}
	slow.expectNone(t)
}

func slowSubscriber(t *testing.T, a *Analyzer, name string) *watchSubscriber {
	t.Helper()
	a.watch.mu.Lock()
	defer a.watch.mu.Unlock()
	for s := range a.watch.subs {
		if s.name == name {
			return s
		}
	}
	t.Fatalf("subscriber %q not found", name)
	return nil
}

func TestWatchDecisionsLeavesNoGoroutines(t *testing.T) {
	a, err := New(Config{EnableWatchAPI: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	clients := []*watchClient{
		startWatch(t, a, "a", nil, 16),
		startWatch(t, a, "b", make(chan struct{}), 16), // stuck in Send
		startWatch(t, a, "c", nil, 16),
	}
	for i := 0; i < 10; i++ {
		a.publishCommand(blockCmd("192.0.2.99"))
	}

	clients[0].cancel()
	if err := clients[0].wait(t); err == nil {
		t.Fatal("disconnect returned nil")
	}
	a.Close()
	if err := clients[2].wait(t); status.Code(err) != codes.Unavailable {
		t.Fatalf("idle handler returned %v after Close", err)
	}
	// A sender stuck in Send is released when gRPC tears the stream down
	// after GracefulStop times out; cancelling its context models that.
	clients[1].cancel()
	if err := clients[1].wait(t); err == nil {
		t.Fatal("stuck handler returned nil")
	}
	if n := a.watch.active.Load(); n != 0 {
		t.Fatalf("active subscribers after Close = %d", n)
	}
	if got := testutil.ToFloat64(metrics.WatchSubscribers); got != 0 {
		t.Fatalf("subscriber gauge = %v after Close", got)
	}

	// Other analyzer components own goroutines of their own, so look for
	// watch frames specifically rather than comparing totals.
	deadline := time.Now().Add(2 * time.Second)
	for {
		buf := make([]byte, 1<<20)
		stacks := string(buf[:runtime.Stack(buf, true)])
		if !strings.Contains(stacks, "(*Analyzer).WatchDecisions") && !strings.Contains(stacks, "(*watchHub)") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("watch goroutines still running:\n%s", stacks)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestWatchDecisionsPublishesPushedRuleSetOnce(t *testing.T) {
	a := newWatchAnalyzer(t, Config{EnableRuleAPI: true})
	addCollector(t, a, "scrub")
	addCollector(t, a, "scrub")
	w := startWatch(t, a, "ctl", nil, 8)

	push(t, a, "ctl", dropRule("x"))

	cmd := w.next(t).GetCommand()
	if cmd.GetType() != apiv1.CommandType_COMMAND_SET_RULES || !cmd.GetRules().GetReplace() {
		t.Fatalf("published %v, want a SET_RULES replacement", cmd)
	}
	if got := upsertIDs(cmd.GetRules()); len(got) != 1 || got[0] != "ctl/x" {
		t.Fatalf("published rules %v, want [ctl/x]", got)
	}
	// Two scrub collectors and the resync must not add more decisions.
	w.expectNone(t)
}
