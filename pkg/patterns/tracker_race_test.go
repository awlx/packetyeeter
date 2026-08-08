package patterns

import (
	"net"
	"sync"
	"testing"
)

// GetPattern must return a snapshot that is safe to read while another
// collector stream keeps mutating the same pattern. Run with -race: this
// fails when the returned copy aliases the live map/slices.
func TestGetPatternSnapshotConcurrentWithRecord(t *testing.T) {
	pt := NewPatternTracker(nil)
	ip := net.ParseIP("203.0.113.5")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range 2000 {
			pt.RecordConnection(ip, ConnectionMetadata{
				PacketSize: 512,
				TTL:        64,
				DestPort:   uint16(1000 + i%50),
			})
		}
	}()
	go func() {
		defer wg.Done()
		for range 2000 {
			p := pt.GetPattern(ip)
			if p == nil {
				continue
			}
			total := uint64(0)
			for _, c := range p.PortsAccessed {
				total += c
			}
			_ = total
			_ = len(p.PacketTimings)
		}
	}()
	wg.Wait()
}
