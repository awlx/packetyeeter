package clockskew

import (
	"net"
	"testing"
)

// Once the profile map is at maxProfiles, every new source IP triggers an
// eviction. Under a spoofed-source flood essentially every packet carries a
// new IP, so eviction cost is paid per packet — this measures that worst case.
func BenchmarkProcessTimestampUniqueIPFlood(b *testing.B) {
	a := NewAnalyzer(nil)
	for i := 0; i <= a.maxProfiles; i++ {
		a.ProcessTimestamp(floodIP(i), uint32(1000+i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.ProcessTimestamp(floodIP(a.maxProfiles+1+i), uint32(1000+i))
	}
}

func floodIP(i int) net.IP {
	return net.IPv4(byte(10+((i>>24)&0x3f)), byte(i>>16), byte(i>>8), byte(i))
}
