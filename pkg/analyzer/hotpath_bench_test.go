package analyzer

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/analyzer/reputation"
)

// These benchmarks never call Start, so no threat-intel, JA4DB or DNS
// lookups leave the process.

type discardStream struct {
	apiv1.AnalyzerService_StreamSignalsServer
}

func (discardStream) Send(*apiv1.Command) error { return nil }

func benchIP(i int) net.IP {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(0x0b000000+i)) // 11.0.0.0/8
	return net.IP(b)
}

func newOfflineAnalyzer(tb testing.TB, dryRun bool) *Analyzer {
	tb.Helper()
	a, err := New(Config{DryRun: dryRun})
	if err != nil {
		tb.Fatalf("New: %v", err)
	}
	tb.Cleanup(a.cancel)
	rep := reputation.New(time.Hour, 0.95, 100)
	tb.Cleanup(rep.Stop)
	a.Reputation = rep
	a.ReputationHelper = NewReputationHelper(rep)
	return a
}

func quietLogs(tb testing.TB) {
	out, lvl := logrus.StandardLogger().Out, logrus.GetLevel()
	logrus.SetOutput(io.Discard)
	logrus.SetLevel(logrus.InfoLevel)
	tb.Cleanup(func() {
		logrus.SetOutput(out)
		logrus.SetLevel(lvl)
	})
}

func BenchmarkTrackBlocked(b *testing.B) {
	quietLogs(b)
	for _, n := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprintf("existing=%d", n), func(b *testing.B) {
			now := time.Now()
			blockedMu.Lock()
			blockedIPs = make(map[string]time.Time, n)
			blockedASNs = make(map[string]time.Time)
			for i := 0; i < n; i++ {
				blockedIPs[benchIP(i).String()] = now
			}
			blockedMu.Unlock()
			ips := make([]net.IP, 1<<16)
			for i := range ips {
				ips[i] = benchIP(n + i)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				trackBlocked(ips[i&(len(ips)-1)], "AS64500")
			}
		})
	}
}

func BenchmarkMarkBlocked(b *testing.B) {
	quietLogs(b)
	for _, n := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprintf("existing=%d", n), func(b *testing.B) {
			a := newOfflineAnalyzer(b, false)
			now := time.Now()
			for i := 0; i < n; i++ {
				a.recentBlocks[benchIP(i).String()] = &blockReservation{at: now, scopes: scopeLocal}
			}
			ips := make([]net.IP, 1<<16)
			for i := range ips {
				ips[i] = benchIP(n + i)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				a.markBlocked(ips[i&(len(ips)-1)])
			}
		})
	}
}

// SYN signals from a fixed IP set with Debug disabled: measures the
// per-signal overhead of the transport-signal path itself.
func BenchmarkProcessSignalSYN(b *testing.B) {
	quietLogs(b)
	a := newOfflineAnalyzer(b, true)
	cs := &collectorStream{stream: discardStream{}}
	sigs := make([]*apiv1.Signal, 16)
	for i := range sigs {
		sigs[i] = &apiv1.Signal{Type: apiv1.SignalType_SIGNAL_SYN_FLOOD, Source: apiv1.SignalSource_SOURCE_EBPF, Ip: benchIP(i), Weight: 10}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.processSignal(sigs[i&15], cs)
	}
}

// Replays processSignal's enforce-mode rate-limited branch for a spoofed
// flood of 40k unique sources: every signal takes trackBlocked, a reputation
// penalty and a deduplicated block command.
func BenchmarkRateLimitedFlood40k(b *testing.B) {
	quietLogs(b)
	const n = 40000
	ips := make([]net.IP, n)
	for i := range ips {
		ips[i] = benchIP(i + 1)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		a := newOfflineAnalyzer(b, false)
		blockedMu.Lock()
		blockedIPs = make(map[string]time.Time)
		blockedASNs = make(map[string]time.Time)
		blockedMu.Unlock()
		cs := &collectorStream{stream: discardStream{}}
		b.StartTimer()
		for _, ip := range ips {
			trackBlocked(ip, "AS64500")
			a.ReputationHelper.PenalizeIP(ip, 10.0, "Rate limit exceeded")
			a.sendCommand(cs, &apiv1.Command{Type: apiv1.CommandType_COMMAND_BLOCK_IP, Ip: ip, Reason: "Rate limit exceeded"}, false)
		}
	}
}
