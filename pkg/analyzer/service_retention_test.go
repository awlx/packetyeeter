package analyzer

import (
	"testing"
	"time"

	"PacketYeeter/pkg/utils/ewma"
)

func TestCleanupTrackingMapsExpiresProxyLagState(t *testing.T) {
	analyzer, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	analyzer.proxyLagByASN["AS64500"] = &ewma.State{
		Value:    100,
		LastTime: time.Now().Add(-time.Hour),
	}

	analyzer.cleanupTrackingMaps()

	if len(analyzer.proxyLagByASN) != 0 {
		t.Fatal("proxy lag EWMA state was not expired")
	}
}
