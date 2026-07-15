package botverify

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestVerifyRemovesInflightEntryOnCachedReturn(t *testing.T) {
	verifier := NewVerifier(time.Hour, time.Second)
	ip := net.ParseIP("192.0.2.10")
	ipStr := ip.String()
	inFlight := &sync.Mutex{}
	inFlight.Lock()

	verifier.mu.Lock()
	verifier.verifyInFlight[ipStr] = inFlight
	verifier.mu.Unlock()

	done := make(chan struct{})
	go func() {
		verifier.Verify(ip, "Googlebot")
		close(done)
	}()

	time.Sleep(10 * time.Millisecond)
	verifier.mu.Lock()
	verifier.cache[ipStr] = &VerificationResult{
		IsVerified: true,
		BotType:    BotTypeGooglebot,
		VerifiedAt: time.Now(),
	}
	verifier.mu.Unlock()
	inFlight.Unlock()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("verification did not finish")
	}

	verifier.mu.RLock()
	_, retained := verifier.verifyInFlight[ipStr]
	verifier.mu.RUnlock()
	if retained {
		t.Fatal("cached return retained the per-IP in-flight mutex")
	}
}
