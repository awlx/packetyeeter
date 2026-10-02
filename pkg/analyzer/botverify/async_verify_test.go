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

func TestVerifyAsyncDropsWhenQueueFull(t *testing.T) {
	v := newTestVerifier(t, time.Minute, 1, 1)
	started := make(chan struct{}, 1)
	v.lookupAddr = func(ctx context.Context, addr string) ([]string, error) {
		started <- struct{}{}
		return hangLookup(ctx, addr)
	}
	rep := newTestReputation()
	h := NewHandler(v, nil, nil, rep)

	busy := net.ParseIP("192.0.2.1")
	if res := h.VerifyBot(busy, googlebotUA, "", ""); !res.Pending {
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
	if res.Pending || res.IsVerified || res.IsImpersonation {
		t.Fatalf("dropped request must be plain unverified, got %+v", res)
	}
	if got := testutil.ToFloat64(drops) - before; got != 1 {
		t.Fatalf("queue_full drops increased by %v, want 1", got)
	}
	if score := rep.GetScore(dropped.String(), reputation.TypeIP); score != 0 {
		t.Fatalf("dropped verification penalized by %v", score)
	}
	if isQueued(v, dropped.String()) {
		t.Fatal("dropped IP must not be marked in flight, or it would stay pending forever")
	}
}

// A backlog of slow lookups must not keep an IP pending, and so exempt from
// the browser-claim heuristics, for longer than an inline lookup would take.
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
	v.queued[ip.String()] = time.Now().Add(-dnsTimeout - time.Second)
	v.mu.Unlock()

	res := h.VerifyBot(ip, googlebotUA, "", "")
	if res.Pending || res.IsVerified || res.IsImpersonation {
		t.Fatalf("pending past dnsTimeout must be plain unverified, got %+v", res)
	}
}

// Pending must not become a permanent heuristics bypass when the verdict
// cannot be cached.
func TestVerifyAsyncDropsWhenCacheFull(t *testing.T) {
	v := newTestVerifier(t, time.Minute, 1, 4)
	v.maxCacheEntries = 1
	v.mu.Lock()
	v.cache["198.51.100.1"] = &VerificationResult{BotType: BotTypeGooglebot, VerifiedAt: time.Now()}
	v.mu.Unlock()

	drops := metrics.BotVerificationQueueDrops.WithLabelValues("cache_full")
	before := testutil.ToFloat64(drops)
	res := v.VerifyAsync(net.ParseIP("192.0.2.9"), googlebotUA)
	if !res.Dropped || res.Pending {
		t.Fatalf("want dropped with a full cache, got %+v", res)
	}
	if got := testutil.ToFloat64(drops) - before; got != 1 {
		t.Fatalf("cache_full drops increased by %v, want 1", got)
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
