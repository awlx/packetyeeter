package entropy

import (
	"net"
	"testing"
)

// Once the profile map is at maxProfiles, every new source IP triggers an
// eviction. Under a spoofed-source flood essentially every packet carries a
// new IP, so eviction cost is paid per packet — this measures that worst case.
func BenchmarkProcessEntropyUniqueIPFlood(b *testing.B) {
	a := NewEntropyAnalyzer(nil)
	for i := 0; i <= a.maxProfiles; i++ {
		a.ProcessEntropy(floodIP(i), 50)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.ProcessEntropy(floodIP(a.maxProfiles+1+i), 50)
	}
}

func floodIP(i int) net.IP {
	return net.IPv4(byte(10+((i>>24)&0x3f)), byte(i>>16), byte(i>>8), byte(i))
}
