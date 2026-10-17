//go:build linux && e2e_ebpf

package collector

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
	"unsafe"

	pyebpf "PacketYeeter/pkg/collector/ebpf"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	maxBenchRepeat = 1 << 24
	warmupRuns     = 16
)

func benchCPUs(b *testing.B) []int {
	b.Helper()
	count := 1
	if v := os.Getenv("YEET_BENCH_CPUS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			b.Fatalf("YEET_BENCH_CPUS=%q: want a positive integer", v)
		}
		count = n
	}
	var allowed unix.CPUSet
	if err := unix.SchedGetaffinity(0, &allowed); err != nil {
		b.Fatalf("get affinity: %v", err)
	}
	cpus := make([]int, 0, count)
	for cpu := 0; cpu < 8*int(unsafe.Sizeof(allowed)) && len(cpus) < count; cpu++ {
		if allowed.IsSet(cpu) {
			cpus = append(cpus, cpu)
		}
	}
	if len(cpus) < count {
		b.Fatalf("YEET_BENCH_CPUS=%d but only %d CPUs are allowed", count, len(cpus))
	}
	return cpus
}

type workerResult struct {
	kernelTotal time.Duration
	runs        int
	err         error
}

func runPinned(cpu int, prog *ebpf.Program, pkt []byte, runs int, start <-chan struct{}) workerResult {
	runtime.LockOSThread()
	var set unix.CPUSet
	set.Set(cpu)
	if err := unix.SchedSetaffinity(0, &set); err != nil {
		return workerResult{err: fmt.Errorf("pin to CPU %d: %w", cpu, err)}
	}
	<-start
	var res workerResult
	for remaining := runs; remaining > 0; {
		repeat := min(remaining, maxBenchRepeat)
		_, perRun, err := prog.Benchmark(pkt, repeat, nil)
		if err != nil {
			return workerResult{err: fmt.Errorf("CPU %d: benchmark run: %w", cpu, err)}
		}
		res.kernelTotal += perRun * time.Duration(repeat)
		res.runs += repeat
		remaining -= repeat
	}
	return res
}

func benchParallel(b *testing.B, prog *ebpf.Program, packet func(worker int) []byte, want uint32) {
	b.Helper()
	cpus := benchCPUs(b)
	pkts := make([][]byte, len(cpus))
	for i := range cpus {
		pkts[i] = packet(i)
	}
	for i, pkt := range pkts {
		ret, _, err := prog.Benchmark(pkt, warmupRuns, nil)
		if err != nil {
			b.Fatalf("warm-up run %d: %v", i, err)
		}
		if ret != want {
			b.Fatalf("warm-up run %d: verdict %d, want %d", i, ret, want)
		}
	}

	start := make(chan struct{})
	results := make([]workerResult, len(cpus))
	var wg sync.WaitGroup
	for i, cpu := range cpus {
		wg.Go(func() {
			results[i] = runPinned(cpu, prog, pkts[i], b.N, start)
		})
	}
	b.ResetTimer()
	close(start)
	wg.Wait()
	b.StopTimer()

	var total time.Duration
	runs := 0
	for _, r := range results {
		if r.err != nil {
			b.Fatal(r.err)
		}
		total += r.kernelTotal
		runs += r.runs
	}
	b.ReportMetric(float64(total.Nanoseconds())/float64(runs), "ns/pkt")
	b.ReportMetric(float64(len(cpus)), "cpus")
}

func benchSport(worker int) uint16 { return uint16(20000 + worker) }

func BenchmarkScrubRuleOverBudgetParallel(b *testing.B) {
	l, _ := loadScrubWithRateRule(b, 1)
	src := net.ParseIP("198.51.100.30").To4()
	benchParallel(b, l.Program("xdp_scrub"), func(worker int) []byte {
		return vIPv4(6, src, vRuleDst4, vTCP(benchSport(worker), tcpACK))
	}, xdpDrop)
}

func BenchmarkBadFlagsRepeatParallel(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("requires root to load eBPF programs")
	}
	l := pyebpf.NewLoader(pyebpf.LoaderConfig{Mode: pyebpf.ModeHost, Interface: "lo"})
	if err := l.Load(); err != nil {
		b.Fatalf("load eBPF: %v", err)
	}
	b.Cleanup(l.Close)
	src := net.ParseIP("198.51.100.20").To4()
	benchParallel(b, l.Program("xdp_filter"), func(worker int) []byte {
		return vIPv4(6, src, vDst4, vTCP(benchSport(worker), tcpSYN|tcpFIN))
	}, xdpDrop)
}

func BenchmarkControlPassInside(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("requires root to load eBPF programs")
	}
	l := pyebpf.NewLoader(pyebpf.LoaderConfig{Mode: pyebpf.ModeScrub, Interface: "lo"})
	if err := l.Load(); err != nil {
		b.Fatalf("load eBPF: %v", err)
	}
	b.Cleanup(l.Close)
	src := net.ParseIP("198.51.100.30").To4()
	benchParallel(b, l.Program("xdp_pass_inside"), func(worker int) []byte {
		return vIPv4(6, src, vRuleDst4, vTCP(benchSport(worker), tcpACK))
	}, xdpPass)
}
