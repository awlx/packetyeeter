package ratelimit

import (
	"net"
	"strconv"
	"testing"
)

// Allow is called for every signal from every collector stream; the common
// case is an existing bucket (hit path). This measures contention across
// goroutines on that path.
func BenchmarkAllowHitPathParallel(b *testing.B) {
	l := NewLimiter(DefaultConfig())
	ips := make([]net.IP, 512)
	asns := make([]string, 16)
	for i := range asns {
		asns[i] = "AS" + strconv.Itoa(64500+i)
	}
	for i := range ips {
		ips[i] = net.IPv4(10, 0, byte(i>>8), byte(i))
		l.Allow(ips[i], asns[i%len(asns)])
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			l.Allow(ips[i%len(ips)], asns[i%len(asns)])
			i++
		}
	})
}
