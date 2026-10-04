package analyzer

import (
	"context"
	"net"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/metrics"
	"PacketYeeter/pkg/ratelimit"
)

func registerRole(t *testing.T, a *Analyzer, role string) (*collectorStream, *fakeCollectorStream) {
	t.Helper()
	fake := newFakeCollectorStream()
	cs := &collectorStream{stream: fake}
	if role != "" {
		cs.setRole(role)
	}
	if id := a.registerCollector(context.Background(), cs); id == "" {
		t.Fatal("collector not admitted")
	}
	return cs, fake
}

func TestScrubBlockReachesEveryScrubCollectorOnce(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})
	w := startWatch(t, a, "ctl", nil, 8)

	scrubA, fakeA := registerRole(t, a, "scrub")
	_, fakeB := registerRole(t, a, "scrub")
	_, host := registerRole(t, a, "host")

	before := testutil.ToFloat64(metrics.ScrubCommandFanout)
	a.sendCommand(scrubA, blockCmd("192.0.2.20"))

	for name, f := range map[string]*fakeCollectorStream{"origin": fakeA, "peer": fakeB} {
		if got := f.waitForCommand(t); got.GetType() != apiv1.CommandType_COMMAND_BLOCK_IP ||
			!net.IP(got.GetIp()).Equal(net.ParseIP("192.0.2.20")) {
			t.Fatalf("%s scrub collector got %v, want BLOCK_IP 192.0.2.20", name, got)
		}
	}
	host.expectNoCommand(t)

	if d := w.next(t); d.GetCommand().GetType() != apiv1.CommandType_COMMAND_BLOCK_IP {
		t.Fatalf("decision = %v, want the block", d)
	}
	w.expectNone(t)
	if got := testutil.ToFloat64(metrics.ScrubCommandFanout) - before; got != 1 {
		t.Fatalf("fan-out sends = %v, want 1", got)
	}

	// Dedup covers the whole fan-out: the peer crossing the threshold next
	// must not re-send.
	a.sendCommand(scrubA, blockCmd("192.0.2.20"))
	fakeA.expectNoCommand(t)
	fakeB.expectNoCommand(t)
	w.expectNone(t)
}

func TestScrubBlockFanoutRespectsDryRun(t *testing.T) {
	a := newWatchAnalyzer(t, Config{DryRun: true})
	w := startWatch(t, a, "ctl", nil, 8)

	scrubA, fakeA := registerRole(t, a, "scrub")
	_, fakeB := registerRole(t, a, "scrub")

	a.sendCommand(scrubA, blockCmd("192.0.2.21"))
	fakeA.expectNoCommand(t)
	fakeB.expectNoCommand(t)
	w.expectNone(t)
}

func TestScrubBlockFanoutRespectsKillSwitch(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})
	scrubA, fakeA := registerRole(t, a, "scrub")
	_, fakeB := registerRole(t, a, "scrub")

	a.enforcement.Stop("test")
	a.sendCommand(scrubA, blockCmd("192.0.2.22"))
	fakeA.expectNoCommand(t)
	fakeB.expectNoCommand(t)
}

func TestHostBlockStaysOnOriginCollector(t *testing.T) {
	a := newWatchAnalyzer(t, Config{})
	w := startWatch(t, a, "ctl", nil, 8)

	// An unannounced role is host mode (collectors before scrub mode).
	hostA, fakeA := registerRole(t, a, "")
	_, fakeB := registerRole(t, a, "host")
	_, scrub := registerRole(t, a, "scrub")

	a.sendCommand(hostA, blockCmd("192.0.2.23"))
	fakeA.waitForCommand(t)
	fakeB.expectNoCommand(t)
	scrub.expectNoCommand(t)
	if d := w.next(t); d.GetCommand().GetType() != apiv1.CommandType_COMMAND_BLOCK_IP {
		t.Fatalf("decision = %v, want the block", d)
	}
	w.expectNone(t)
}

// Rate-limit evidence is keyed by source IP, not by collector, so a source
// split over two scrub nodes is judged on its total.
func TestSplitSourceAcrossScrubNodesJudgedOnTotal(t *testing.T) {
	a := newTestAnalyzer(t)
	a.AIEngine = nil
	a.Config.ReputationThreshold = 1e9
	noRefill := 0.0
	a.RateLimiter = ratelimit.NewLimiter(ratelimit.Config{IPRateExact: &noRefill, IPBurst: 10})

	scrubA, fakeA := registerRole(t, a, "scrub")
	scrubB, fakeB := registerRole(t, a, "scrub")

	signal := func(ip string) *apiv1.Signal {
		return &apiv1.Signal{
			Type:   apiv1.SignalType_SIGNAL_TCP_METADATA,
			Source: apiv1.SignalSource_SOURCE_EBPF,
			Ip:     net.ParseIP(ip).To4(),
		}
	}

	// Control: 6 signals from one node alone stay under the burst of 10.
	for range 6 {
		a.processSignal(signal("198.51.100.1"), scrubA)
	}
	fakeA.expectNoCommand(t)
	fakeB.expectNoCommand(t)

	// 6 + 6 from two nodes exceed it.
	for range 6 {
		a.processSignal(signal("198.51.100.2"), scrubA)
		a.processSignal(signal("198.51.100.2"), scrubB)
	}
	for name, f := range map[string]*fakeCollectorStream{"A": fakeA, "B": fakeB} {
		got := f.waitForCommand(t)
		if !net.IP(got.GetIp()).Equal(net.ParseIP("198.51.100.2")) {
			t.Fatalf("node %s got %v, want BLOCK_IP 198.51.100.2", name, got)
		}
	}
	fakeA.expectNoCommand(t)
	fakeB.expectNoCommand(t)
}
