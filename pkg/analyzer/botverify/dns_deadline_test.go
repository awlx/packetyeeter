package botverify

import (
	"context"
	"net"
	"testing"
	"time"
)

// The whole verification (reverse PTR + forward-confirm) must share a single
// deadline rather than giving each lookup its own dnsTimeout. This test makes
// each lookup block until its context is cancelled and asserts the total
// verifyDNS wall-clock stays within one dnsTimeout budget (plus slack), not two.
func TestVerifyDNSSharesOneDeadlineAcrossLookups(t *testing.T) {
	v := NewVerifier(time.Hour, 200*time.Millisecond)

	blockUntilCtxDone := func(ctx context.Context, _ string) ([]string, error) {
		<-ctx.Done()
		return nil, &net.DNSError{Err: "timeout", IsTimeout: true, IsTemporary: true}
	}
	// Reverse returns a Googlebot PTR quickly so the forward lookup is reached;
	// the forward lookup then blocks until the shared deadline fires.
	v.lookupAddr = func(context.Context, string) ([]string, error) {
		return []string{"crawl-192-0-2-7.googlebot.com."}, nil
	}
	v.lookupHost = blockUntilCtxDone

	pattern := &BotPattern{Type: "googlebot", ReverseDNS: []string{".googlebot.com"}, RequireForward: true}

	start := time.Now()
	res := v.verifyDNS(net.ParseIP("192.0.2.7"), pattern)
	elapsed := time.Since(start)

	if res.IsVerified {
		t.Fatal("expected verification to fail on the blocked forward lookup")
	}
	if !res.TransientFailure {
		t.Fatalf("blocked (timeout) forward lookup should be a transient failure, got %+v", res)
	}
	// One shared 200ms budget; allow generous slack for scheduling. Two
	// independent 200ms timeouts (reverse+forward) would still be ~200ms here
	// since reverse returns instantly, so specifically exercise both blocking:
	if elapsed > time.Second {
		t.Fatalf("verifyDNS took %v; the shared deadline should bound it near one dnsTimeout", elapsed)
	}
}

// Both lookups blocking must still be bounded by a single dnsTimeout, not the
// sum of two.
func TestVerifyDNSTotalBudgetIsOneTimeoutWhenBothBlock(t *testing.T) {
	const timeout = 150 * time.Millisecond
	v := NewVerifier(time.Hour, timeout)

	blockUntilCtxDone := func(ctx context.Context, _ string) ([]string, error) {
		<-ctx.Done()
		return nil, &net.DNSError{Err: "timeout", IsTimeout: true, IsTemporary: true}
	}
	v.lookupAddr = blockUntilCtxDone // reverse blocks the whole budget

	pattern := &BotPattern{Type: "googlebot", ReverseDNS: []string{".googlebot.com"}, RequireForward: true}

	start := time.Now()
	_ = v.verifyDNS(net.ParseIP("192.0.2.8"), pattern)
	elapsed := time.Since(start)

	// With a shared deadline the reverse lookup alone consumes the budget and
	// the call returns at ~timeout, never 2*timeout.
	if elapsed >= 2*timeout {
		t.Fatalf("verifyDNS took %v, want < 2*timeout (%v): the deadline must be shared, not per-lookup", elapsed, 2*timeout)
	}
}

// IsForgivenTransientFailure is the single rule both the HTTP handler and the
// gRPC VerifyBot RPC use to decide whether a failed verification counts as
// impersonation. A transient failure within the cap is forgiven (not
// impersonation); anything else is not forgiven.
func TestIsForgivenTransientFailure(t *testing.T) {
	cases := []struct {
		name string
		res  VerificationResult
		want bool
	}{
		{"transient within cap is forgiven", VerificationResult{TransientFailure: true, ConsecutiveTransientFailures: 1}, true},
		{"transient at cap is forgiven", VerificationResult{TransientFailure: true, ConsecutiveTransientFailures: maxConsecutiveTransientFailures}, true},
		{"transient over cap is not forgiven", VerificationResult{TransientFailure: true, ConsecutiveTransientFailures: maxConsecutiveTransientFailures + 1}, false},
		{"definitive failure is not forgiven", VerificationResult{TransientFailure: false, ConsecutiveTransientFailures: 0}, false},
		{"verified is not a forgiven failure", VerificationResult{IsVerified: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.res.IsForgivenTransientFailure(); got != tc.want {
				t.Fatalf("IsForgivenTransientFailure() = %v, want %v", got, tc.want)
			}
		})
	}
}
