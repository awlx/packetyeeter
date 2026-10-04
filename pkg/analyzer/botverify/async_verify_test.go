package botverify

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"PacketYeeter/pkg/analyzer/reputation"
	"PacketYeeter/pkg/metrics"
)

// hangLookup never answers, like a tarpitting PTR zone, until its context ends.
func hangLookup(ctx context.Context, _ string) ([]string, error) {
	<-ctx.Done()
	return nil, &net.DNSError{Err: "timeout", IsTimeout: true, IsTemporary: true}
}

// noNetwork fails any lookup that reaches the real resolver.
func noNetwork(t *testing.T) func(context.Context, string) ([]string, error) {
	return func(context.Context, string) ([]string, error) {
		t.Error("unexpected DNS lookup")
		return nil, &net.DNSError{Err: "unexpected lookup", IsNotFound: true}
	}
}

func newTestVerifier(t *testing.T, dnsTimeout time.Duration, workers, queue int) *Verifier {
	t.Helper()
	v := newVerifier(time.Hour, dnsTimeout, nil, workers, queue)
	v.lookupAddr = noNetwork(t)
	v.lookupHost = noNetwork(t)
	t.Cleanup(v.Close)
	return v
}

func newTestReputation() *reputation.Engine {
	rep := reputation.New(time.Minute, 0.5, 100)
	rep.SetIPScoreCap(1000)
	return rep
}

// seedCache stores a verdict as a finished lookup would.
func seedCache(v *Verifier, ipStr string, res *VerificationResult) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.storeLocked(ipStr, res)
}

func isQueued(v *Verifier, ipStr string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	_, ok := v.queued[ipStr]
	return ok
}

// waitSettled waits until no lookup for ip is queued or running.
func waitSettled(t *testing.T, v *Verifier, ip net.IP) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for isQueued(v, ip.String()) {
		if time.Now().After(deadline) {
			t.Fatalf("verification of %s did not finish", ip)
		}
		time.Sleep(time.Millisecond)
	}
}

// verifyBotSettled is VerifyBot as seen by the first request after the async
// lookup has finished.
func verifyBotSettled(t *testing.T, h *Handler, v *Verifier, ip net.IP, ua string) *VerifyResult {
	t.Helper()
	res := h.VerifyBot(ip, ua, "AS64496", "Example")
	if !res.Pending {
		return res
	}
	waitSettled(t, v, ip)
	res = h.VerifyBot(ip, ua, "AS64496", "Example")
	if res.Pending {
		t.Fatalf("still pending after the lookup finished: %+v", res)
	}
	return res
}

// The DoS: with a PTR server that never answers, each new bot-claiming IP used
// to stall the collector's signal stream for the full DNS timeout.
func TestVerifyBotDoesNotWaitOnHungDNS(t *testing.T) {
	v := newTestVerifier(t, time.Minute, 4, 256)
	v.lookupAddr = hangLookup
	rep := newTestReputation()
	h := NewHandler(v, nil, nil, rep)

	for i := range 100 {
		ip := net.IPv4(192, 0, 2, byte(i+1))
		start := time.Now()
		res := h.VerifyBot(ip, googlebotUA, "AS64496", "Example")
		if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
			t.Fatalf("request %d took %v with a hung resolver", i, elapsed)
		}
		if !res.Pending || res.IsVerified || res.IsImpersonation {
			t.Fatalf("request %d: want pending (not verified, not impersonation), got %+v", i, res)
		}
		if score := rep.GetScore(ip.String(), reputation.TypeIP); score != 0 {
			t.Fatalf("pending verification penalized %s by %v", ip, score)
		}
	}
}

func TestVerifyAsyncDeduplicatesInFlightIP(t *testing.T) {
	v := newTestVerifier(t, time.Minute, 4, 16)
	var lookups atomic.Int32
	release := make(chan struct{})
	v.lookupAddr = func(ctx context.Context, _ string) ([]string, error) {
		lookups.Add(1)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}

	ip := net.ParseIP("192.0.2.50")
	for range 200 {
		if res := v.VerifyAsync(ip, googlebotUA); !res.Pending {
			t.Fatalf("want pending while lookup is in flight, got %+v", res)
		}
	}
	close(release)
	waitSettled(t, v, ip)

	if n := lookups.Load(); n != 1 {
		t.Fatalf("200 requests from one IP caused %d lookups, want 1", n)
	}
	if res := v.VerifyAsync(ip, googlebotUA); res.Pending || res.IsVerified {
		t.Fatalf("want cached definitive failure after the lookup, got %+v", res)
	}
}

// A full queue must not turn a crawler's first requests into unverified ones
// (that is the lookup-flood lever), but the pending pass it gets instead is
// bounded per IP, and the lookup is retried once there is room.
func TestVerifyAsyncQueueFullStaysPendingWithinWindow(t *testing.T) {
	const dnsTimeout = time.Minute
	v := newTestVerifier(t, dnsTimeout, 1, 1)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	v.lookupAddr = func(ctx context.Context, addr string) ([]string, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}
	rep := newTestReputation()
	h := NewHandler(v, nil, nil, rep)

	if res := h.VerifyBot(net.ParseIP("192.0.2.1"), googlebotUA, "", ""); !res.Pending {
		t.Fatalf("first request: want pending, got %+v", res)
	}
	<-started // the only worker is now stuck
	if res := h.VerifyBot(net.ParseIP("192.0.2.2"), googlebotUA, "", ""); !res.Pending {
		t.Fatalf("second request should fill the queue, got %+v", res)
	}

	drops := metrics.BotVerificationQueueDrops.WithLabelValues("queue_full")
	before := testutil.ToFloat64(drops)
	dropped := net.ParseIP("192.0.2.3")
	start := time.Now()
	res := h.VerifyBot(dropped, googlebotUA, "", "")
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("dropped request took %v", elapsed)
	}
	if !res.Pending || res.IsVerified || res.IsImpersonation {
		t.Fatalf("queue-full request within its window: want pending, got %+v", res)
	}
	if got := testutil.ToFloat64(drops) - before; got != 1 {
		t.Fatalf("queue_full drops increased by %v, want 1", got)
	}
	if score := rep.GetScore(dropped.String(), reputation.TypeIP); score != 0 {
		t.Fatalf("dropped verification penalized by %v", score)
	}
	if isQueued(v, dropped.String()) {
		t.Fatal("a lookup that was not queued must not be marked in flight")
	}

	v.mu.Lock()
	v.pendingSince[dropped.String()] = time.Now().Add(-dnsTimeout - time.Second)
	v.mu.Unlock()
	if res := h.VerifyBot(dropped, googlebotUA, "", ""); res.Pending || res.IsVerified || res.IsImpersonation {
		t.Fatalf("past its pending window: want plain unverified, got %+v", res)
	}

	close(release)
	waitSettled(t, v, net.ParseIP("192.0.2.2"))
	h.VerifyBot(dropped, googlebotUA, "", "")
	waitSettled(t, v, dropped)
	if res := h.VerifyBot(dropped, googlebotUA, "", ""); !res.IsImpersonation {
		t.Fatalf("the dropped lookup must be retried once the queue drains, got %+v", res)
	}
}

// A backlog of slow lookups must not keep an IP pending, and so exempt from
// the crawler heuristics, for longer than an inline lookup would take.
func TestVerifyAsyncPendingIsBoundedByDNSTimeout(t *testing.T) {
	const dnsTimeout = time.Minute
	v := newTestVerifier(t, dnsTimeout, 1, 8)
	v.lookupAddr = hangLookup
	h := NewHandler(v, nil, nil, newTestReputation())

	ip := net.ParseIP("192.0.2.30")
	if res := h.VerifyBot(ip, googlebotUA, "", ""); !res.Pending {
		t.Fatalf("first request: want pending, got %+v", res)
	}
	v.mu.Lock()
	v.pendingSince[ip.String()] = time.Now().Add(-dnsTimeout - time.Second)
	v.mu.Unlock()

	res := h.VerifyBot(ip, googlebotUA, "", "")
	if res.Pending || res.IsVerified || res.IsImpersonation {
		t.Fatalf("pending past dnsTimeout must be plain unverified, got %+v", res)
	}

	// Waiting out the window does not buy a fresh one.
	v.prunePending(time.Now())
	if res := h.VerifyBot(ip, googlebotUA, "", ""); res.Pending {
		t.Fatalf("pending window renewed before its cooldown, got %+v", res)
	}
}

func TestVerifyAsyncPendingTableIsBounded(t *testing.T) {
	v := newTestVerifier(t, time.Minute, 1, 4)
	v.lookupAddr = hangLookup
	v.maxPendingTracked = 2
	for i := range 2 {
		if res := v.VerifyAsync(net.IPv4(192, 0, 2, byte(i+1)), googlebotUA); !res.Pending {
			t.Fatalf("request %d: want pending, got %+v", i, res)
		}
	}
	drops := metrics.BotVerificationQueueDrops.WithLabelValues("pending_full")
	before := testutil.ToFloat64(drops)
	if res := v.VerifyAsync(net.ParseIP("192.0.2.9"), googlebotUA); !res.Dropped || res.Pending {
		t.Fatalf("want dropped with a full pending table, got %+v", res)
	}
	if got := testutil.ToFloat64(drops) - before; got != 1 {
		t.Fatalf("pending_full drops increased by %v, want 1", got)
	}
}

// Fake crawler claims fill only the unverified pool: they evict each other,
// never a verified crawler, and a new verdict always finds room.
func TestCacheEvictionPrefersUnverified(t *testing.T) {
	v := newTestVerifier(t, time.Minute, 1, 4)
	v.maxCacheEntries = 3
	crawler := "198.51.100.1"
	seedCache(v, crawler, &VerificationResult{IsVerified: true, BotType: BotTypeGooglebot, VerifiedAt: time.Now()})

	for i := range 10 {
		seedCache(v, fmt.Sprintf("192.0.2.%d", i+1), &VerificationResult{BotType: BotTypeGooglebot, VerifiedAt: time.Now(), ErrorMessage: "reverse DNS mismatch"})
	}
	if got := v.cachedResult(crawler); got == nil || !got.IsVerified {
		t.Fatalf("verified crawler evicted by fake claims: %+v", got)
	}
	v.mu.RLock()
	n, unverified := len(v.cache), v.unverifiedLRU.Len()
	v.mu.RUnlock()
	if unverified != 3 || n != 4 {
		t.Fatalf("pools not bounded: %d entries, %d unverified", n, unverified)
	}
	for i := 7; i < 10; i++ {
		if v.cachedResult(fmt.Sprintf("192.0.2.%d", i+1)) == nil {
			t.Fatalf("newest unverified verdict 192.0.2.%d was evicted instead of the oldest", i+1)
		}
	}
	if v.cachedResult("192.0.2.1") != nil {
		t.Fatal("oldest unverified verdict was not evicted")
	}
}

// An expired verified verdict revalidates as Pending, whatever the queue.
func TestExpiredVerifiedRevalidatesAsPending(t *testing.T) {
	v := newTestVerifier(t, time.Minute, 1, 1)
	v.lookupAddr = hangLookup
	ip := net.ParseIP("198.51.100.7")
	seedCache(v, ip.String(), &VerificationResult{IsVerified: true, BotType: BotTypeGooglebot, VerifiedAt: time.Now().Add(-2 * time.Hour)})
	// Fill the worker and the queue.
	v.VerifyAsync(net.ParseIP("192.0.2.1"), googlebotUA)
	v.VerifyAsync(net.ParseIP("192.0.2.2"), googlebotUA)
	v.VerifyAsync(net.ParseIP("192.0.2.3"), googlebotUA)

	v.mu.Lock()
	v.pendingSince[ip.String()] = time.Now().Add(-time.Hour)
	v.mu.Unlock()
	if res := v.VerifyAsync(ip, googlebotUA); !res.Pending || res.IsVerified {
		t.Fatalf("expired verified IP: want pending revalidation, got %+v", res)
	}
}

// After Close every lookup fails as cancelled; that must not be cached as a
// transient failure against the IP.
func TestSyncVerifyAfterCloseIsNotCached(t *testing.T) {
	v := newVerifier(time.Hour, time.Second, nil, 1, 1)
	v.lookupAddr = func(ctx context.Context, _ string) ([]string, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	v.Close()
	res := v.Verify(net.ParseIP("192.0.2.70"), googlebotUA)
	if !res.Dropped || res.TransientFailure || res.IsVerified {
		t.Fatalf("want dropped after Close, got %+v", res)
	}
	if v.cachedResult("192.0.2.70") != nil {
		t.Fatal("cancelled lookup was cached")
	}
}

func TestAsyncVerdictAppliesToNextRequest(t *testing.T) {
	t.Run("impersonation", func(t *testing.T) {
		v := newTestVerifier(t, time.Second, 2, 8)
		v.lookupAddr = func(context.Context, string) ([]string, error) {
			return []string{"host.evil.example."}, nil
		}
		rep := newTestReputation()
		h := NewHandler(v, nil, nil, rep)
		ip := net.ParseIP("192.0.2.66")

		first := h.VerifyBot(ip, googlebotUA, "", "")
		if !first.Pending || first.IsImpersonation {
			t.Fatalf("first request: want pending, got %+v", first)
		}
		if score := rep.GetScore(ip.String(), reputation.TypeIP); score != 0 {
			t.Fatalf("pending request penalized by %v", score)
		}
		waitSettled(t, v, ip)

		next := h.VerifyBot(ip, googlebotUA, "", "")
		if !next.IsImpersonation || next.Pending {
			t.Fatalf("next request: want impersonation from the cached verdict, got %+v", next)
		}
		if score := rep.GetScore(ip.String(), reputation.TypeIP); score == 0 {
			t.Fatal("impersonation verdict must penalize reputation")
		}
	})

	t.Run("verified", func(t *testing.T) {
		v := newTestVerifier(t, time.Second, 2, 8)
		ip := net.ParseIP("192.0.2.67")
		v.lookupAddr = func(context.Context, string) ([]string, error) {
			return []string{"crawl-192-0-2-67.googlebot.com."}, nil
		}
		v.lookupHost = func(context.Context, string) ([]string, error) {
			return []string{ip.String()}, nil
		}
		h := NewHandler(v, nil, nil, newTestReputation())

		if first := h.VerifyBot(ip, googlebotUA, "", ""); !first.Pending || first.IsVerified {
			t.Fatalf("first request: want pending and not yet verified, got %+v", first)
		}
		if next := verifyBotSettled(t, h, v, ip, googlebotUA); !next.IsVerified {
			t.Fatalf("next request: want verified, got %+v", next)
		}
	})
}

// Close must cancel lookups stuck on DNS and stop every pool goroutine.
func TestCloseStopsPoolWithLookupsInFlight(t *testing.T) {
	baseline := runtime.NumGoroutine()

	v := newVerifier(time.Hour, time.Hour, nil, 8, 64)
	var running atomic.Int32
	v.lookupAddr = func(ctx context.Context, addr string) ([]string, error) {
		running.Add(1)
		return hangLookup(ctx, addr)
	}
	for i := range 32 {
		v.VerifyAsync(net.ParseIP(fmt.Sprintf("192.0.2.%d", i+1)), googlebotUA)
	}
	deadline := time.Now().Add(5 * time.Second)
	for running.Load() < 8 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d workers started a lookup", running.Load())
		}
		time.Sleep(time.Millisecond)
	}

	closed := make(chan struct{})
	go func() {
		v.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return: in-flight lookups ignored cancellation")
	}

	for runtime.NumGoroutine() > baseline {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			t.Fatalf("goroutines leaked: %d > baseline %d\n%s", runtime.NumGoroutine(), baseline, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(time.Millisecond)
	}

	res := v.VerifyAsync(net.ParseIP("192.0.2.200"), googlebotUA)
	if res.Pending {
		t.Fatalf("closed verifier must not report pending, got %+v", res)
	}
	v.mu.RLock()
	cached := len(v.cache)
	v.mu.RUnlock()
	if cached != 0 {
		t.Fatalf("lookups cut short by Close were cached as verdicts (%d entries)", cached)
	}
}
