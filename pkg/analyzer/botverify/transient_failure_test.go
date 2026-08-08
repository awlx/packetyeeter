package botverify

import (
	"net"
	"testing"
	"time"

	"PacketYeeter/pkg/analyzer/reputation"
)

func TestIsTransientDNSError(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		transient bool
	}{
		{"nxdomain is definitive", &net.DNSError{Err: "no such host", IsNotFound: true}, false},
		{"timeout is transient", &net.DNSError{Err: "i/o timeout", IsTimeout: true}, true},
		{"servfail is transient", &net.DNSError{Err: "server misbehaving", IsTemporary: true}, true},
		{"unknown error is transient", net.ErrClosed, true},
	}
	for _, tc := range cases {
		if got := isTransientDNSError(tc.err); got != tc.transient {
			t.Errorf("%s: isTransientDNSError = %v, want %v", tc.name, got, tc.transient)
		}
	}
}

// A transient verification failure must expire quickly instead of pinning the
// IP unverified for the full cacheTTL.
func TestTransientResultUsesShortTTL(t *testing.T) {
	v := NewVerifier(time.Hour, time.Second)

	transient := &VerificationResult{
		BotType:          BotTypeGooglebot,
		VerifiedAt:       time.Now().Add(-2 * transientFailTTL),
		TransientFailure: true,
		ErrorMessage:     "reverse DNS failed",
	}
	if ttl := v.cachedResultTTL(transient); ttl != transientFailTTL {
		t.Fatalf("transient TTL = %v, want %v", ttl, transientFailTTL)
	}

	definitive := &VerificationResult{BotType: BotTypeGooglebot, VerifiedAt: time.Now()}
	if ttl := v.cachedResultTTL(definitive); ttl != time.Hour {
		t.Fatalf("definitive TTL = %v, want %v", ttl, time.Hour)
	}
}

// A transient DNS failure must not apply the impersonation penalty: one
// resolver hiccup on a real crawler followed by per-request re-penalties
// would ban it within seconds.
func TestTransientFailureDoesNotPenalize(t *testing.T) {
	rep := reputation.New(time.Minute, 0.5, 100)
	// The IP score cap defaults to 0, which clamps every IP penalty back to
	// 0; lift it so a GetScore==0 assertion actually proves no penalty was
	// applied rather than passing trivially.
	rep.SetIPScoreCap(1000)
	v := NewVerifier(time.Hour, time.Second)
	h := NewHandler(v, nil, nil, rep)

	ip := net.ParseIP("192.0.2.77")
	ipStr := ip.String()

	// Pre-seed the verifier cache with a transient failure, as verifyDNS
	// produces on a resolver timeout.
	v.mu.Lock()
	v.cache[ipStr] = &VerificationResult{
		BotType:          BotTypeGooglebot,
		VerifiedAt:       time.Now(),
		TransientFailure: true,
		ErrorMessage:     "reverse DNS failed",
	}
	v.mu.Unlock()

	result := h.VerifyBot(ip, "Mozilla/5.0 (compatible; Googlebot/2.1)", "AS15169", "Google LLC")
	if result.IsImpersonation {
		t.Fatal("transient failure must not be classified as impersonation")
	}
	if score := rep.GetScore(ipStr, reputation.TypeIP); score != 0 {
		t.Fatalf("transient failure penalized reputation by %v, want 0", score)
	}
}

const googlebotUA = "Mozilla/5.0 (compatible; Googlebot/2.1)"

// servfailLookup simulates an attacker-controlled PTR zone that answers
// SERVFAIL forever (transient class, never NXDOMAIN).
func servfailLookup(string) ([]string, error) {
	return nil, &net.DNSError{Err: "server misbehaving", IsTemporary: true}
}

// expireCachedResult rewinds the cached entry's VerifiedAt so the next
// Verify call re-verifies instead of serving the cache, simulating the
// passage of one re-verification cycle.
func expireCachedResult(t *testing.T, v *Verifier, ipStr string, age time.Duration) {
	t.Helper()
	v.mu.Lock()
	defer v.mu.Unlock()
	entry, ok := v.cache[ipStr]
	if !ok {
		t.Fatalf("expected cached verification result for %s", ipStr)
	}
	entry.VerifiedAt = time.Now().Add(-age)
}

// Exploit regression: an attacker controls the PTR zone for their own IP
// block and can force SERVFAIL/timeouts indefinitely while sending a
// Googlebot User-Agent. Unbounded forgiveness of transient DNS failures
// would be a permanent impersonation free pass. After
// maxConsecutiveTransientFailures forgiven cycles, verification must fail
// closed: impersonation + reputation penalty, like a definitive failure.
func TestRepeatedTransientFailuresEventuallyPenalize(t *testing.T) {
	rep := reputation.New(time.Minute, 0.5, 100)
	rep.SetIPScoreCap(1000)
	v := NewVerifier(time.Hour, time.Second)
	v.lookupAddr = servfailLookup
	h := NewHandler(v, nil, nil, rep)

	ip := net.ParseIP("192.0.2.88")
	ipStr := ip.String()

	for i := 1; i <= maxConsecutiveTransientFailures; i++ {
		result := h.VerifyBot(ip, googlebotUA, "AS64496", "Evil VPS")
		if result.IsImpersonation {
			t.Fatalf("cycle %d: penalized before the forgiveness cap", i)
		}
		if score := rep.GetScore(ipStr, reputation.TypeIP); score != 0 {
			t.Fatalf("cycle %d: reputation penalized by %v before the cap", i, score)
		}
		expireCachedResult(t, v, ipStr, 2*transientFailTTL)
	}

	result := h.VerifyBot(ip, googlebotUA, "AS64496", "Evil VPS")
	if !result.IsImpersonation {
		t.Fatalf("after %d consecutive transient failures the free pass must end (got IsImpersonation=false)", maxConsecutiveTransientFailures+1)
	}
	if score := rep.GetScore(ipStr, reputation.TypeIP); score == 0 {
		t.Fatal("over-cap transient failure must penalize reputation like a definitive failure")
	}
}

// A definitive result (here a successful verification) between transient
// failures must reset the consecutive counter, so a genuinely flaky crawler
// that intermittently verifies never accumulates toward the cap. Guards
// against the counter latching permanently for legitimate intermittent PTR.
func TestDefinitiveResultResetsTransientCounter(t *testing.T) {
	v := NewVerifier(time.Hour, time.Second)
	ip := net.ParseIP("192.0.2.99")
	ipStr := ip.String()

	// Point the reverse lookup at a Googlebot PTR and make forward DNS
	// resolve back to the IP, so verifyDNS returns a definitive success.
	v.lookupAddr = func(string) ([]string, error) { return []string{"crawl-192-0-2-99.googlebot.com."}, nil }
	v.lookupHost = func(string) ([]string, error) { return []string{ipStr}, nil }

	// Accumulate transient failures just under the cap.
	v.lookupAddr = servfailLookup
	for range maxConsecutiveTransientFailures {
		v.Verify(ip, googlebotUA)
		expireCachedResult(t, v, ipStr, 2*transientFailTTL)
	}
	v.mu.RLock()
	got := v.cache[ipStr].ConsecutiveTransientFailures
	v.mu.RUnlock()
	if got != maxConsecutiveTransientFailures {
		t.Fatalf("expected counter %d before reset, got %d", maxConsecutiveTransientFailures, got)
	}

	// One definitive success resets the counter.
	v.lookupAddr = func(string) ([]string, error) { return []string{"crawl-192-0-2-99.googlebot.com."}, nil }
	res := v.Verify(ip, googlebotUA)
	if !res.IsVerified {
		t.Fatalf("expected definitive verification, got %+v", res)
	}
	if res.ConsecutiveTransientFailures != 0 {
		t.Fatalf("definitive result must reset counter to 0, got %d", res.ConsecutiveTransientFailures)
	}

	// A subsequent transient failure starts counting from 1 again, proving the
	// reset really cleared state rather than merely masking it.
	expireCachedResult(t, v, ipStr, 2*v.cacheTTL)
	v.lookupAddr = servfailLookup
	res = v.Verify(ip, googlebotUA)
	if res.ConsecutiveTransientFailures != 1 {
		t.Fatalf("post-reset transient failure must restart at 1, got %d", res.ConsecutiveTransientFailures)
	}
}
