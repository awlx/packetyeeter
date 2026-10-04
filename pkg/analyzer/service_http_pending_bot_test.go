package analyzer

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/analyzer/aidetection"
	"PacketYeeter/pkg/analyzer/botverify"
	"PacketYeeter/pkg/analyzer/reputation"
	"PacketYeeter/pkg/metrics"
)

// pendingExemptSignals are the heuristics a real crawler trips (Googlebot's
// Chrome-embedded UA, no cookies or Accept-Language, a "bot" UA keyword) and
// is exempt from once verified.
var pendingExemptSignals = []aidetection.SignalType{
	aidetection.SignalMissingSecFetch,
	aidetection.SignalMissingSecCH,
	aidetection.SignalAcceptMismatch,
	aidetection.SignalTLSVersionMismatch,
	aidetection.SignalHeaderOrderAnomaly,
	aidetection.SignalBotUA,
	aidetection.SignalMissingAcceptLang,
	aidetection.SignalNoCookies,
	aidetection.SignalNoReferer,
}

func signalCounts() map[aidetection.SignalType]float64 {
	m := map[aidetection.SignalType]float64{}
	for _, st := range pendingExemptSignals {
		m[st] = testutil.ToFloat64(metrics.AIEngineSignalIngressByType.WithLabelValues(string(aidetection.CanonicalizeSignalType(st))))
	}
	return m
}

func googlebotRequest(ip net.IP) *apiv1.Signal {
	return &apiv1.Signal{
		Ip: ip.To4(),
		Metadata: map[string]string{
			"header_order": "host,user-agent,accept",
		},
		HttpContext: &apiv1.HTTPContext{
			Method:     "GET",
			Path:       "/",
			UserAgent:  "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.199 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			Accept:     "*/*",
			TlsVersion: "TLSv1.0",
		},
	}
}

// A Googlebot claim from a new IP behind a PTR server that never answers: the
// signal stream must not wait on DNS, and while verification is pending the
// request gets neither the impersonation penalty nor the heuristics a
// verified crawler is exempt from.
func TestPendingBotVerificationDoesNotBlockOrPenalize(t *testing.T) {
	a := newPendingBotAnalyzer(t)
	before := signalCounts()
	pendingBefore := testutil.ToFloat64(metrics.BotVerificationPending.WithLabelValues(string(botverify.BotTypeGooglebot)))

	const requests = 20
	for i := range requests {
		ip := net.IPv4(192, 0, 2, byte(i+1))
		start := time.Now()
		a.processHTTPRequest(googlebotRequest(ip), ip, "AS64496", &collectorStream{})
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("request %d took %v: the signal path waited on DNS", i, elapsed)
		}
		if score := a.Reputation.GetScore(ip.String(), reputation.TypeIP); score != 0 {
			t.Fatalf("pending verification penalized %s by %v", ip, score)
		}
	}

	after := signalCounts()
	for _, st := range pendingExemptSignals {
		if after[st] != before[st] {
			t.Errorf("%s emitted %v time(s) while verification was pending, want 0", st, after[st]-before[st])
		}
	}
	if got := testutil.ToFloat64(metrics.BotVerificationPending.WithLabelValues(string(botverify.BotTypeGooglebot))) - pendingBefore; got != requests {
		t.Errorf("pending verdicts counted %v, want %d", got, requests)
	}
}

// Without a pending verdict (here: verifier closed, so Dropped) the same
// request gets every heuristic again; the exemption is tied to Pending only.
func TestNonPendingBotClaimGetsHeuristics(t *testing.T) {
	a := newPendingBotAnalyzer(t)
	a.BotVerifier.Close()
	before := signalCounts()
	ip := net.IPv4(192, 0, 2, 200)
	a.processHTTPRequest(googlebotRequest(ip), ip, "AS64496", &collectorStream{})
	after := signalCounts()
	for _, st := range []aidetection.SignalType{aidetection.SignalBotUA, aidetection.SignalMissingAcceptLang, aidetection.SignalNoCookies} {
		if after[st] == before[st] {
			t.Errorf("%s not emitted for an unverified bot claim", st)
		}
	}
}

func newPendingBotAnalyzer(t *testing.T) *Analyzer {
	t.Helper()
	cfg := Config{DryRun: true}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New(cfg) failed: %v", err)
	}
	a.Reputation = reputation.New(30*time.Minute, 0.95, cfg.ReputationThreshold)
	a.Reputation.SetIPScoreCap(1000)
	a.ReputationHelper = NewReputationHelper(a.Reputation)
	engine := aidetection.New(aidetection.Config{Workers: 1, BufferSize: 4096})
	a.SignalBuilder = aidetection.NewSignalBuilder(engine)

	a.BotVerifier = botverify.NewVerifierWithGeoIP(time.Hour, 5*time.Second, nil)
	// Dial is ours and never connects: no real DNS, every lookup hangs until
	// its context ends.
	a.BotVerifier.SetResolver(&net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})
	t.Cleanup(a.BotVerifier.Close)
	a.BotHandler = botverify.NewHandler(a.BotVerifier, nil, a.SignalBuilder, a.Reputation)

	return a
}
