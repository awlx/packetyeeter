//go:build linux && e2e_ebpf

// Runs the real eBPF programs through BPF_PROG_TEST_RUN over a fixed packet
// corpus and checks verdicts and map side effects, so hot-path changes can be
// shown not to change what gets dropped. Needs root and `make bpf`:
//
//	sudo -E go test -tags e2e_ebpf -run 'TestXDPVerdicts|TestSynMonitor' -v ./pkg/collector/
//
// YEET_BPF_OBJ points it at another object, e.g. a build of the base branch.
package collector

import (
	"encoding/binary"
	"net"
	"os"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	xdpDrop = 1
	xdpPass = 2
)

var (
	vBlocked4 = net.ParseIP("198.51.100.10").To4()
	vScan4    = net.ParseIP("198.51.100.20").To4()
	vClean4   = net.ParseIP("198.51.100.30").To4()
	vPolBlk4  = net.ParseIP("203.0.113.5").To4()
	vPolMon4  = net.ParseIP("192.0.2.5").To4()
	vDst4     = net.ParseIP("10.99.0.2").To4()

	vBlocked6 = net.ParseIP("2001:db8:1::10")
	vScan6    = net.ParseIP("2001:db8:1::20")
	vClean6   = net.ParseIP("2001:db8:1::30")
	vPolBlk6  = net.ParseIP("2001:db8:bad::5")
	vPolMon6  = net.ParseIP("2001:db8:a0::5")
	vDst6     = net.ParseIP("2001:db8:99::2")
)

const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
	tcpURG = 0x20
)

func bpfObjPath() string {
	if p := os.Getenv("YEET_BPF_OBJ"); p != "" {
		return p
	}
	return "ebpf/c/protector.bpf.o"
}

// loadPrograms mirrors the loader: only the named programs, all maps.
func loadPrograms(t *testing.T, names ...string) *ebpf.Collection {
	t.Helper()
	requireRoot(t)
	spec, err := ebpf.LoadCollectionSpec(bpfObjPath())
	if err != nil {
		t.Fatalf("load spec %s (run make bpf): %v", bpfObjPath(), err)
	}
	keep := map[string]bool{}
	for _, n := range names {
		keep[n] = true
	}
	for n := range spec.Programs {
		if !keep[n] {
			delete(spec.Programs, n)
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("new collection: %v", err)
	}
	t.Cleanup(coll.Close)
	return coll
}

func vEth(proto uint16) []byte {
	b := make([]byte, 14)
	copy(b[0:6], []byte{2, 0, 0, 0, 0, 1})
	copy(b[6:12], []byte{2, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(b[12:], proto)
	return b
}

func vIPv4(proto byte, src, dst net.IP, l4 []byte) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)))
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], src.To4())
	copy(ip[16:20], dst.To4())
	var s uint32
	for i := 0; i < 20; i += 2 {
		s += uint32(binary.BigEndian.Uint16(ip[i:]))
	}
	for s > 0xffff {
		s = s>>16 + s&0xffff
	}
	binary.BigEndian.PutUint16(ip[10:], ^uint16(s))
	return append(append(vEth(0x0800), ip...), l4...)
}

func vIPv6(next byte, src, dst net.IP, l4 []byte) []byte {
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(l4)))
	ip[6] = next
	ip[7] = 64
	copy(ip[8:24], src.To16())
	copy(ip[24:40], dst.To16())
	return append(append(vEth(0x86dd), ip...), l4...)
}

// vTCP carries Linux-style SYN options so the JA4T timestamp parse runs.
func vTCP(sport uint16, flags byte) []byte {
	opts := []byte{2, 4, 0x05, 0xb4, 4, 2, 8, 10, 1, 2, 3, 4, 0, 0, 0, 0, 1, 3, 3, 7}
	b := make([]byte, 20+len(opts))
	binary.BigEndian.PutUint16(b[0:], sport)
	binary.BigEndian.PutUint16(b[2:], 80)
	binary.BigEndian.PutUint32(b[4:], 1)
	b[12] = byte(len(b)/4) << 4
	b[13] = flags
	binary.BigEndian.PutUint16(b[14:], 64240)
	copy(b[20:], opts)
	return b
}

func vUDP() []byte {
	b := make([]byte, 8+32)
	binary.BigEndian.PutUint16(b[0:], 40000)
	binary.BigEndian.PutUint16(b[2:], 53)
	binary.BigEndian.PutUint16(b[4:], uint16(len(b)))
	return b
}

func vICMP(v6 bool) []byte {
	b := make([]byte, 16)
	b[0] = 8
	if v6 {
		b[0] = 128
	}
	return b
}

func v4Key(ip net.IP) uint32 { return binary.LittleEndian.Uint32(ip.To4()) }

func v6Key(ip net.IP) [16]byte {
	var k [16]byte
	copy(k[:], ip.To16())
	return k
}

type lpm4 struct {
	Plen uint32
	Addr [4]byte
}

type lpm6 struct {
	Plen uint32
	Addr [16]byte
}

type badFlags struct {
	LastSeen uint64
	ScanType uint32
	FlagsRaw uint32
}

const blockStart = uint64(123456789)

// seedMaps installs one blocked source and one BLOCK and one MONITOR policy
// per family.
func seedMaps(t *testing.T, coll *ebpf.Collection, monitor bool) {
	t.Helper()
	put := func(m string, k, v any) {
		if err := coll.Maps[m].Put(k, v); err != nil {
			t.Fatalf("seed %s: %v", m, err)
		}
	}
	put("blocked_ips", v4Key(vBlocked4), blockStart)
	put("blocked_ips_v6", v6Key(vBlocked6), blockStart)
	var a4 [4]byte
	copy(a4[:], vPolBlk4)
	put("policy_v4", lpm4{24, a4}, uint32(1))
	copy(a4[:], vPolMon4)
	put("policy_v4", lpm4{24, a4}, uint32(2))
	put("policy_v6", lpm6{48, v6Key(vPolBlk6)}, uint32(1))
	put("policy_v6", lpm6{48, v6Key(vPolMon6)}, uint32(2))
	mon := uint32(0)
	if monitor {
		mon = 1
	}
	put("config_map", uint32(1), mon)
}

type vCase struct {
	name string
	pkt  []byte
	drop bool // in enforcing mode; monitor mode never drops
}

func verdictCorpus() []vCase {
	xmas := byte(tcpFIN | tcpPSH | tcpURG)
	return []vCase{
		{"v4 blocked udp", vIPv4(17, vBlocked4, vDst4, vUDP()), true},
		{"v4 blocked tcp ack", vIPv4(6, vBlocked4, vDst4, vTCP(1000, tcpACK)), true},
		{"v4 xmas", vIPv4(6, vScan4, vDst4, vTCP(1001, xmas)), true},
		{"v4 syn fin", vIPv4(6, vScan4, vDst4, vTCP(1002, tcpSYN|tcpFIN)), true},
		{"v4 null", vIPv4(6, vScan4, vDst4, vTCP(1003, 0)), true},
		{"v4 syn", vIPv4(6, vClean4, vDst4, vTCP(1004, tcpSYN)), false},
		{"v4 ack", vIPv4(6, vClean4, vDst4, vTCP(1005, tcpACK)), false},
		{"v4 rst", vIPv4(6, vClean4, vDst4, vTCP(1006, tcpRST)), false},
		{"v4 udp", vIPv4(17, vClean4, vDst4, vUDP()), false},
		{"v4 icmp", vIPv4(1, vClean4, vDst4, vICMP(false)), false},
		{"v4 policy block", vIPv4(17, vPolBlk4, vDst4, vUDP()), true},
		{"v4 policy monitor xmas", vIPv4(6, vPolMon4, vDst4, vTCP(1007, xmas)), false},
		{"v6 blocked udp", vIPv6(17, vBlocked6, vDst6, vUDP()), true},
		{"v6 blocked tcp ack", vIPv6(6, vBlocked6, vDst6, vTCP(1000, tcpACK)), true},
		{"v6 xmas", vIPv6(6, vScan6, vDst6, vTCP(1001, xmas)), true},
		{"v6 syn fin", vIPv6(6, vScan6, vDst6, vTCP(1002, tcpSYN|tcpFIN)), true},
		{"v6 null", vIPv6(6, vScan6, vDst6, vTCP(1003, 0)), true},
		{"v6 syn", vIPv6(6, vClean6, vDst6, vTCP(1004, tcpSYN)), false},
		{"v6 ack", vIPv6(6, vClean6, vDst6, vTCP(1005, tcpACK)), false},
		{"v6 udp", vIPv6(17, vClean6, vDst6, vUDP()), false},
		{"v6 icmp", vIPv6(58, vClean6, vDst6, vICMP(true)), false},
		{"v6 policy block", vIPv6(17, vPolBlk6, vDst6, vUDP()), true},
		{"v6 policy monitor xmas", vIPv6(6, vPolMon6, vDst6, vTCP(1007, xmas)), false},
	}
}

func runProg(t *testing.T, p *ebpf.Program, pkt []byte, repeat uint32) uint32 {
	t.Helper()
	ret, err := p.Run(&ebpf.RunOptions{Data: pkt, Repeat: repeat})
	if err != nil {
		t.Fatalf("test run: %v", err)
	}
	return ret
}

func TestXDPVerdicts(t *testing.T) {
	for _, prog := range []string{"xdp_filter", "xdp_scrub"} {
		for _, monitor := range []bool{false, true} {
			name := prog + "/enforce"
			if monitor {
				name = prog + "/monitor"
			}
			t.Run(name, func(t *testing.T) {
				coll := loadPrograms(t, prog)
				seedMaps(t, coll, monitor)
				p := coll.Programs[prog]
				for _, c := range verdictCorpus() {
					got := runProg(t, p, c.pkt, 1)
					t.Logf("verdict %s: %d", c.name, got)
					wantDrop := c.drop && !monitor
					if (got == xdpDrop) != wantDrop {
						t.Errorf("%s: verdict %d, want drop=%v", c.name, got, wantDrop)
					}
					// Host mode hands every surviving packet to the stack; the
					// scrub verdict depends on the test netns's routes.
					if prog == "xdp_filter" && !wantDrop && got != xdpPass {
						t.Errorf("%s: verdict %d, want XDP_PASS", c.name, got)
					}
				}
				checkBlockedUnchanged(t, coll, p)
				checkRepeatedScan(t, coll, p)
			})
		}
	}
}

// Drops must not write the blocked value: block GC expires on it.
func checkBlockedUnchanged(t *testing.T, coll *ebpf.Collection, p *ebpf.Program) {
	t.Helper()
	runProg(t, p, vIPv4(17, vBlocked4, vDst4, vUDP()), 1000)
	runProg(t, p, vIPv6(17, vBlocked6, vDst6, vUDP()), 1000)
	var v uint64
	if err := coll.Maps["blocked_ips"].Lookup(v4Key(vBlocked4), &v); err != nil {
		t.Fatalf("blocked_ips lookup: %v", err)
	}
	if v != blockStart {
		t.Errorf("blocked_ips value %d after drops, want %d (drift %d)", v, blockStart, v-blockStart)
	}
	if err := coll.Maps["blocked_ips_v6"].Lookup(v6Key(vBlocked6), &v); err != nil {
		t.Fatalf("blocked_ips_v6 lookup: %v", err)
	}
	if v != blockStart {
		t.Errorf("blocked_ips_v6 value %d after drops, want %d", v, blockStart)
	}
}

// A repeat scanner keeps one entry whose fields follow the latest packet.
func checkRepeatedScan(t *testing.T, coll *ebpf.Collection, p *ebpf.Program) {
	t.Helper()
	src4 := net.ParseIP("198.51.100.77").To4()
	src6 := net.ParseIP("2001:db8:1::77")
	for _, fam := range []struct {
		name string
		m    *ebpf.Map
		key  any
		pkt  func(flags byte) []byte
	}{
		{"v4", coll.Maps["bad_flags"], v4Key(src4), func(f byte) []byte { return vIPv4(6, src4, vDst4, vTCP(2000, f)) }},
		{"v6", coll.Maps["bad_flags_v6"], v6Key(src6), func(f byte) []byte { return vIPv6(6, src6, vDst6, vTCP(2000, f)) }},
	} {
		var first, second, third badFlags
		runProg(t, p, fam.pkt(tcpFIN|tcpPSH|tcpURG), 1)
		if err := fam.m.Lookup(fam.key, &first); err != nil {
			t.Fatalf("%s: no bad_flags entry after a scan: %v", fam.name, err)
		}
		if first.ScanType != 2 || first.FlagsRaw != tcpFIN|tcpPSH|tcpURG || first.LastSeen == 0 {
			t.Errorf("%s: first scan entry %+v", fam.name, first)
		}
		runProg(t, p, fam.pkt(tcpFIN|tcpPSH|tcpURG), 1)
		if err := fam.m.Lookup(fam.key, &second); err != nil {
			t.Fatalf("%s: bad_flags entry gone after a repeat scan: %v", fam.name, err)
		}
		if second.LastSeen <= first.LastSeen || second.ScanType != 2 {
			t.Errorf("%s: repeat scan %+v, first %+v: last_seen must advance", fam.name, second, first)
		}
		runProg(t, p, fam.pkt(tcpSYN|tcpFIN), 1)
		if err := fam.m.Lookup(fam.key, &third); err != nil {
			t.Fatalf("%s: bad_flags lookup: %v", fam.name, err)
		}
		if third.LastSeen <= second.LastSeen || third.ScanType != 1 || third.FlagsRaw != tcpSYN|tcpFIN {
			t.Errorf("%s: changed scan %+v, previous %+v", fam.name, third, second)
		}
	}
}

type emitBudget struct {
	WindowStart uint64
	Count       uint64
}

// Handshake tracking must keep running once the per-CPU event budget is spent.
func TestSynMonitorTracksPastEventBudget(t *testing.T) {
	coll := loadPrograms(t, "tc_ingress_syn_monitor")
	p := coll.Programs["tc_ingress_syn_monitor"]

	// One CPU, so all SYNs draw from one budget.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var set unix.CPUSet
	set.Set(0)
	if err := unix.SchedSetaffinity(0, &set); err != nil {
		t.Fatalf("pin to CPU 0: %v", err)
	}

	const syns = 1500
	src4, src6 := net.ParseIP("198.51.100.40").To4(), net.ParseIP("2001:db8:1::40")
	for i := 0; i < syns; i++ {
		sport := uint16(10000 + i)
		if ret := runProg(t, p, vIPv4(6, src4, vDst4, vTCP(sport, tcpSYN)), 1); ret != 0 {
			t.Fatalf("v4 SYN %d: verdict %d, want TC_ACT_OK", i, ret)
		}
		if ret := runProg(t, p, vIPv6(6, src6, vDst6, vTCP(sport, tcpSYN)), 1); ret != 0 {
			t.Fatalf("v6 SYN %d: verdict %d, want TC_ACT_OK", i, ret)
		}
	}

	var budgets []emitBudget
	if err := coll.Maps["event_budget"].Lookup(uint32(0), &budgets); err != nil {
		t.Fatalf("event_budget lookup: %v", err)
	}
	if budgets[0].Count < 1000 {
		t.Fatalf("CPU 0 event budget count %d: the test never exhausted it", budgets[0].Count)
	}

	countPending[[12]byte](t, "v4", coll.Maps["pending_handshakes"], syns)
	countPending[[36]byte](t, "v6", coll.Maps["pending_handshakes_v6"], syns)
}

func countPending[K any](t *testing.T, name string, m *ebpf.Map, want int) {
	t.Helper()
	var k K
	var v struct {
		BeginTime  uint64
		SynackTime uint64
		SynackSent uint8
		Pad        [7]uint8
	}
	n := 0
	it := m.Iterate()
	for it.Next(&k, &v) {
		if v.BeginTime == 0 || v.SynackSent != 0 {
			t.Errorf("%s: entry %v has %+v", name, k, v)
		}
		n++
	}
	if err := it.Err(); err != nil {
		t.Fatalf("%s: iterate: %v", name, err)
	}
	if n != want {
		t.Errorf("%s: %d pending handshakes after %d SYNs, want one per SYN", name, n, want)
	}
}
