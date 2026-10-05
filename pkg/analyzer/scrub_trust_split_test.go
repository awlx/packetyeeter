package analyzer

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/analyzer/aidetection"
	"PacketYeeter/pkg/analyzer/reputation"
	"PacketYeeter/pkg/metrics"
	"PacketYeeter/pkg/ratelimit"
)

// newSplitAnalyzer has trusted names, a trusted reputation and the given
// shared and trusted limiters.
func newSplitAnalyzer(t *testing.T, shared, trusted ratelimit.Config) *Analyzer {
	t.Helper()
	a := newTestAnalyzer(t)
	allowScrubNames(a)
	a.AIEngine = nil
	a.Config.ReputationThreshold = 50
	for _, old := range []*ratelimit.Limiter{a.RateLimiter, a.ScrubRateLimiter} {
		if old != nil {
			old.Stop()
		}
	}
	a.RateLimiter = ratelimit.NewLimiter(shared)
	a.ScrubRateLimiter = ratelimit.NewLimiter(trusted)
	t.Cleanup(a.RateLimiter.Stop)
	t.Cleanup(a.ScrubRateLimiter.Stop)
	srep := reputation.New(time.Hour, 0.95, 50)
	t.Cleanup(srep.Stop)
	a.ScrubReputation = srep
	return a
}

func zeroRefillIP(burst float64) ratelimit.Config {
	noRefill := 0.0
	return ratelimit.Config{IPRateExact: &noRefill, IPBurst: burst, ASNBurst: 1e6}
}

func zeroRefillASN(burst float64) ratelimit.Config {
	noRefill := 0.0
	return ratelimit.Config{IPBurst: 1e6, ASNRateExact: &noRefill, ASNBurst: burst}
}

// An untrusted collector keeps the shared bucket of a source drained. The
// trusted scrub stream's signal for that source trips only the shared
// limiter: it gets no rate-limit block, the skip is counted, and the signal
// still reaches the AI engine and the trusted reputation check.
func TestSharedOnlyTripKeepsTrustedAnalysis(t *testing.T) {
	a := newSplitAnalyzer(t, zeroRefillIP(10), zeroRefillIP(10))
	engine := aidetection.New(aidetection.Config{Workers: 1, BufferSize: 64})
	a.AIEngine = engine

	rogueFake := newBufferedFake(64)
	rogue := registerStream(t, a, "host", "", rogueFake)
	scrubA, fakeA := registerTrusted(t, a, "scrub")
	_, fakeB := registerTrusted(t, a, "scrub")

	const victim = "198.51.100.120"
	for range 11 {
		a.processSignal(tcpSignal(victim), rogue)
	}
	if got := rogueFake.waitForCommand(t); got.GetReason() != "Rate limit exceeded" {
		t.Fatalf("rogue got %v, want its own rate-limit block", got)
	}
	a.ScrubReputation.Penalize(victim, reputation.TypeIP, 80, "trusted")

	ingress := metrics.AIEngineSignalIngressByType.WithLabelValues(string(aidetection.SignalTCPMetadata))
	aiBefore := testutil.ToFloat64(ingress)
	skipped := testutil.ToFloat64(metrics.ScrubSharedOnlyBlocksSkipped.WithLabelValues("rate_limit"))
	tripsBefore := testutil.ToFloat64(metrics.RateLimitExceeded.WithLabelValues("ip"))

	a.processSignal(tcpSignal(victim), scrubA)

	if got := testutil.ToFloat64(ingress) - aiBefore; got != 1 {
		t.Fatalf("AI engine got %v signals from the trusted stream, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.ScrubSharedOnlyBlocksSkipped.WithLabelValues("rate_limit")) - skipped; got != 1 {
		t.Fatalf("skipped shared-only rate-limit blocks = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.RateLimitExceeded.WithLabelValues("ip")) - tripsBefore; got != 0 {
		t.Fatalf("skipped trip counted as %v rate-limit trips, want 0", got)
	}
	for name, f := range map[string]*fakeCollectorStream{"A": fakeA, "B": fakeB} {
		if got := f.waitForCommand(t); !strings.HasPrefix(got.GetReason(), "Reputation threshold exceeded") {
			t.Fatalf("scrub %s got %v, want the trusted reputation block", name, got)
		}
	}
	rogueFake.expectNoCommand(t)
}

// The same over the HTTP path, with the shared bucket drained per IP or per
// ASN (other sources of the same ASN): the trusted request still reaches
// the sustained-download feed and the trusted reputation check.
func TestSharedOnlyTripKeepsTrustedHTTPAnalysis(t *testing.T) {
	const asn = "AS64500"
	httpSig := func(ip string) *apiv1.Signal {
		return &apiv1.Signal{
			Type:   apiv1.SignalType_SIGNAL_HTTP_REQUEST,
			Source: apiv1.SignalSource_SOURCE_SPOE,
			Ip:     net.ParseIP(ip).To4(),
			HttpContext: &apiv1.HTTPContext{
				Method:    "GET",
				Host:      "example.com",
				Path:      "/",
				UserAgent: "curl/8.0",
			},
		}
	}
	for name, tc := range map[string]struct {
		shared  ratelimit.Config
		drainIP func(i int) string
	}{
		"ip bucket":  {zeroRefillIP(10), func(int) string { return "198.51.100.130" }},
		"asn bucket": {zeroRefillASN(10), func(i int) string { return fmt.Sprintf("203.0.113.%d", 10+i) }},
	} {
		t.Run(name, func(t *testing.T) {
			a := newSplitAnalyzer(t, tc.shared, zeroRefillIP(10))
			rogueFake := newBufferedFake(64)
			rogue := registerStream(t, a, "host", "", rogueFake)
			scrubA, fakeA := registerTrusted(t, a, "scrub")
			_, fakeB := registerTrusted(t, a, "scrub")

			for i := range 10 {
				ip := tc.drainIP(i)
				a.processHTTPRequest(httpSig(ip), net.ParseIP(ip), asn, rogue)
			}
			const victim = "198.51.100.130"
			a.ScrubReputation.Penalize(victim, reputation.TypeIP, 80, "trusted")
			skipped := testutil.ToFloat64(metrics.ScrubSharedOnlyBlocksSkipped.WithLabelValues("rate_limit"))

			a.processHTTPRequest(httpSig(victim), net.ParseIP(victim), asn, scrubA)

			if got := testutil.ToFloat64(metrics.ScrubSharedOnlyBlocksSkipped.WithLabelValues("rate_limit")) - skipped; got != 1 {
				t.Fatalf("skipped shared-only rate-limit blocks = %v, want 1", got)
			}
			for name, f := range map[string]*fakeCollectorStream{"A": fakeA, "B": fakeB} {
				if got := f.waitForCommand(t); !strings.HasPrefix(got.GetReason(), "HTTP reputation threshold exceeded") {
					t.Fatalf("scrub %s got %v, want the trusted reputation block", name, got)
				}
			}
		})
	}
}

// Untrusted rewards to the shared score (a browser JA4, say) must not spare
// a source the trusted reputation puts over the threshold.
func TestUntrustedRewardDoesNotSuppressTrustedReputationBlock(t *testing.T) {
	a := newSplitAnalyzer(t, zeroRefillIP(1e6), zeroRefillIP(1e6))
	scrubA, fakeA := registerTrusted(t, a, "scrub")
	_, fakeB := registerTrusted(t, a, "scrub")
	host, hostFake := registerRole(t, a, "host")

	const victim = "198.51.100.140"
	a.Reputation.Penalize(victim, reputation.TypeIP, 80, "trusted trips")
	a.ScrubReputation.Penalize(victim, reputation.TypeIP, 80, "trusted trips")
	for range 20 {
		a.ReputationHelper.RewardIP(net.ParseIP(victim), 50, "browser JA4 (untrusted)")
	}
	if got := a.Reputation.GetScore(victim, reputation.TypeIP); got > a.Config.ReputationThreshold {
		t.Fatalf("shared score %v still over the threshold after the rewards", got)
	}

	a.processSignal(tcpSignal(victim), scrubA)
	for name, f := range map[string]*fakeCollectorStream{"A": fakeA, "B": fakeB} {
		if got := f.waitForCommand(t); !net.IP(got.GetIp()).Equal(net.ParseIP(victim)) {
			t.Fatalf("scrub %s got %v, want the trusted reputation block", name, got)
		}
	}

	// A host collector is still judged on the shared score.
	a.processSignal(tcpSignal(victim), host)
	hostFake.expectNoCommand(t)
}
