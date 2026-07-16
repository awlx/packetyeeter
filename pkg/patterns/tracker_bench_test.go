package patterns

import (
	"net"
	"testing"
)

// Once the pattern map is at maxPatterns, every new source IP triggers an
// eviction. Under a spoofed-source flood essentially every packet carries a
// new IP, so eviction cost is paid per packet — this measures that worst case.
func BenchmarkRecordConnectionUniqueIPFlood(b *testing.B) {
	pt := NewPatternTracker(nil)
	meta := ConnectionMetadata{TTL: 64, WindowSize: 65535, MSS: 1460}
	for i := 0; i <= pt.maxPatterns; i++ {
		pt.RecordConnection(floodIP(i), meta)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pt.RecordConnection(floodIP(pt.maxPatterns+1+i), meta)
	}
}

func floodIP(i int) net.IP {
	return net.IPv4(byte(10+((i>>24)&0x3f)), byte(i>>16), byte(i>>8), byte(i))
}
