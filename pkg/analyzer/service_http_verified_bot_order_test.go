package analyzer

import (
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

// TestVerifiedBotSkipsHeaderImpersonationSignals is a regression guard for a
// production false-positive where verified crawlers (e.g. Googlebot's
// Chrome-embedded mobile rendering UA, which legitimately omits
// Sec-Fetch-*/sends "Accept: */*" and doesn't negotiate modern TLS the same
// way a real end-user Chrome session would) still triggered
// missing_sec_ch/missing_sec_fetch/accept_mismatch/tls_version_mismatch -
// in one observed production case crossing the block confidence threshold.
//
// processHTTPRequest used to run the header/UA impersonation heuristics
// (which infer "claims to be a browser but isn't behaving like one") before
// calling BotHandler.VerifyBot, so even a request that verification would
// later confirm as a known-good bot had already had these signals fired
// against it. BotHandler.VerifyBot must run first so verified bots are
// excluded from these heuristics entirely, matching how they're already
// excluded from the JA4 fingerprint analysis further down.
//
// This test uses the AI-crawler trusted-ASN verification path (Amazonbot +
// AS14618/AS16509), which is fully deterministic and requires no network
// access, unlike the DNS-based verifier used for Googlebot/Facebook/etc.
func TestVerifiedBotSkipsHeaderImpersonationSignals(t *testing.T) {
	// A UA that would trip every one of the header/UA impersonation
	// heuristics under the old (pre-reorder) code: it claims to be a real
	// Chrome browser (isChromeFamilyUA), but sends none of Sec-Fetch-*,
	// sends a bare wildcard Accept, and negotiated an outdated TLS version -
	// while also being a verifiable Amazonbot crawler request.
	sig := &apiv1.Signal{
		Ip: net.ParseIP("34.222.0.1").To4(),
		HttpContext: &apiv1.HTTPContext{
			UserAgent:    "Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot) Chrome/119.0.6045.214 Safari/537.36",
			Accept:       "*/*",
			SecFetchSite: "",
			SecFetchMode: "",
			SecFetchDest: "",
			TlsVersion:   "TLSv1.0",
		},
	}
	ip := net.ParseIP("34.222.0.1")
	const trustedAmazonASN = "AS16509"

	cfg := Config{DryRun: true}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New(cfg) failed: %v", err)
	}
	a.Reputation = reputation.New(30*time.Minute, 0.95, cfg.ReputationThreshold)
	a.ReputationHelper = NewReputationHelper(a.Reputation)

	engine := aidetection.New(aidetection.Config{Workers: 1, BufferSize: 1})
	a.SignalBuilder = aidetection.NewSignalBuilder(engine)

	// New() alone doesn't wire up bot verification (that happens in the
	// heavier Start(), which also spins up JA4DB downloads, pprof, etc.) -
	// construct just the BotHandler piece directly, mirroring what Start()
	// does, to keep this test focused and side-effect free.
	a.BotVerifier = botverify.NewVerifierWithGeoIP(1*time.Hour, 5*time.Second, nil)
	a.AICrawlers = botverify.NewAICrawlerRegistry(1 * time.Hour)
	a.BotHandler = botverify.NewHandler(a.BotVerifier, a.AICrawlers, a.SignalBuilder, a.Reputation)

	// Fill the single-slot queue so any signal emitted by
	// processHTTPRequest overflows and is counted as a drop, letting us
	// detect emission without waiting out the engine's evaluation window.
	engine.EmitSignal(aidetection.Signal{Type: aidetection.SignalTCPMetadata, IP: net.ParseIP("198.51.100.1")})

	before := testutil.ToFloat64(metrics.AIEngineQueueDrops)
	a.processHTTPRequest(sig, ip, trustedAmazonASN, &collectorStream{})
	after := testutil.ToFloat64(metrics.AIEngineQueueDrops)

	if got := after - before; got != 0 {
		t.Errorf("verified bot request caused %v additional signal(s) to be queued; want 0 (verification should short-circuit before header/UA heuristics run)", got)
	}
}
