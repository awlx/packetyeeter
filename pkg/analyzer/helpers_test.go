package analyzer

import (
	"fmt"
	"net"
	"sync"
	"testing"
)

// trackBlocked is called from per-collector gRPC stream handler goroutines, so
// it must be safe for concurrent use. Run with -race: this fails with
// "concurrent map writes" when blockedIPs/blockedASNs are unsynchronized.
func TestTrackBlockedConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				ip := net.ParseIP(fmt.Sprintf("192.0.2.%d", (g*200+i)%256))
				trackBlocked(ip, fmt.Sprintf("AS%d", g))
			}
		}(g)
	}
	wg.Wait()
}
