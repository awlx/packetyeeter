package botverify

import (
	"context"
	"net"
	"testing"
	"time"
)

// Verify runs inline on the signal-stream goroutine, so DNS verification must
// return within dnsTimeout even against a resolver that never answers (e.g.
// an attacker-controlled tarpitting PTR zone).
func TestVerifyHonorsDNSTimeout(t *testing.T) {
	const dnsTimeout = 100 * time.Millisecond
	v := NewVerifier(time.Hour, dnsTimeout)
	v.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	start := time.Now()
	result := v.Verify(net.ParseIP("192.0.2.10"), "Mozilla/5.0 (compatible; Googlebot/2.1)")
	elapsed := time.Since(start)

	if result.IsVerified {
		t.Fatal("verification must fail when DNS never answers")
	}
	if elapsed > 10*dnsTimeout {
		t.Fatalf("Verify blocked for %v; want return within ~%v", elapsed, dnsTimeout)
	}
}
