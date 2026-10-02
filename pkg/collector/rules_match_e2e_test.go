//go:build linux && e2e_ebpf

// Differential test of the XDP rule matcher: random rules and packets are run
// through xdp_scrub with BPF_PROG_TEST_RUN and every verdict is compared with
// a plain Go matcher written from the rule semantics. Requires root and the
// eBPF object built by `make bpf`:
//
//	sudo -E go test -tags e2e_ebpf -run TestScrubRuleMatcher ./pkg/collector/
package collector

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"net/netip"
	"slices"
	"testing"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/collector/ebpf"

	cebpf "github.com/cilium/ebpf"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type testPkt struct {
	v6           bool
	src, dst     netip.Addr
	proto        uint8
	sport, dport uint16
	hasPorts     bool
	tcpFlags     uint8
	hasTCP       bool
	length       uint16 // IP total length
	frag         bool
	data         []byte
}

var (
	ruleTestDsts4 = []string{"198.51.100.10", "198.51.100.77"}
	ruleTestDsts6 = []string{"2001:db8:5::10", "2001:db8:5::77"}
	ruleTestPorts = []uint16{1, 22, 53, 80, 99, 100, 101, 123, 443, 1023, 1024, 5000, 8080, 65534, 65535}
	// Flag sets that the bad-flags check never drops.
	ruleTestFlags = []uint8{0x02, 0x10, 0x12, 0x18, 0x14, 0x11, 0x04}
)

func pick[T any](r *rand.Rand, xs []T) T { return xs[r.Intn(len(xs))] }

func randSrc(r *rand.Rand, v6 bool) netip.Addr {
	if v6 {
		return netip.MustParseAddr(fmt.Sprintf("2001:db8:%d::%d", 1+r.Intn(2), r.Intn(24)))
	}
	return netip.AddrFrom4([4]byte{10, 0, byte(r.Intn(2)), byte(r.Intn(24))})
}

func randPrefix(r *rand.Rand, v6, sameLen bool, bits int) netip.Prefix {
	if !sameLen {
		if v6 {
			bits = pick(r, []int{124, 126, 128})
		} else {
			bits = pick(r, []int{28, 30, 32})
		}
	}
	p, _ := randSrc(r, v6).Prefix(bits)
	return p
}

func randRanges(r *rand.Rand) []*apiv1.PortRange {
	var out []*apiv1.PortRange
	for range r.Intn(9) {
		a, b := pick(r, ruleTestPorts), pick(r, ruleTestPorts)
		if r.Intn(3) == 0 {
			b = a
		}
		if a > b {
			a, b = b, a
		}
		out = append(out, &apiv1.PortRange{From: uint32(a), To: uint32(b)})
	}
	return out
}

func randRule(r *rand.Rand, id int) *apiv1.Rule {
	v6 := r.Intn(3) == 0
	var dst string
	if v6 {
		dst = pick(r, []string{"2001:db8:5::10/128", "2001:db8:5::/64", "2001:db8::/32"})
	} else {
		dst = pick(r, []string{"198.51.100.10/32", "198.51.100.77/32", "198.51.100.0/24", "198.51.0.0/16"})
	}
	pr := &apiv1.Rule{
		Id:        fmt.Sprintf("r%d", id),
		DstPrefix: dst,
		Action:    apiv1.RuleAction_RULE_ACTION_DROP,
		Priority:  uint32(r.Intn(5)),
		ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
	}
	pr.Protocols = pick(r, [][]uint32{nil, {6}, {17}, {6, 17}, {1}, {6, 1}})
	if !(len(pr.Protocols) > 0 && !slices.Contains(pr.Protocols, 6) && !slices.Contains(pr.Protocols, 17)) {
		if r.Intn(2) == 0 {
			pr.SrcPorts = randRanges(r)
		}
		if r.Intn(2) == 0 {
			pr.DstPorts = randRanges(r)
		}
	}
	if (len(pr.Protocols) == 0 || slices.Contains(pr.Protocols, 6)) && r.Intn(4) == 0 {
		mask := uint32(pick(r, []uint8{0x02, 0x10, 0x12, 0x17}))
		pr.TcpFlagsMask, pr.TcpFlagsValue = mask, mask&uint32(pick(r, ruleTestFlags))
	}
	if r.Intn(4) == 0 {
		a, b := uint32(20+r.Intn(150)), uint32(20+r.Intn(150))
		if a > b {
			a, b = b, a
		}
		pr.PktLen = &apiv1.PortRange{From: a, To: b}
	}
	if !v6 && r.Intn(5) == 0 {
		f := r.Intn(2) == 0
		pr.Fragment = &f
	}
	if r.Intn(3) != 0 {
		sameLen, bits := r.Intn(2) == 0, 32
		if v6 {
			bits = 128
		}
		if sameLen && r.Intn(2) == 0 {
			bits -= 4
		}
		for range 1 + r.Intn(8) {
			pr.SrcPrefixes = append(pr.SrcPrefixes, randPrefix(r, v6, sameLen, bits).String())
		}
	}
	return pr
}

func buildPkt(r *rand.Rand) testPkt {
	p := testPkt{v6: r.Intn(3) == 0}
	p.src = randSrc(r, p.v6)
	if p.v6 {
		p.dst = netip.MustParseAddr(pick(r, ruleTestDsts6))
	} else {
		p.dst = netip.MustParseAddr(pick(r, ruleTestDsts4))
	}
	p.proto = pick(r, []uint8{6, 17, 17, 6, 1})
	p.sport, p.dport = pick(r, ruleTestPorts), pick(r, ruleTestPorts)
	payload := r.Intn(120)

	var l4 []byte
	switch p.proto {
	case 6:
		p.tcpFlags = pick(r, ruleTestFlags)
		l4 = make([]byte, 20+payload)
		binary.BigEndian.PutUint16(l4[0:], p.sport)
		binary.BigEndian.PutUint16(l4[2:], p.dport)
		l4[12] = 5 << 4
		l4[13] = p.tcpFlags
		binary.BigEndian.PutUint16(l4[14:], 64240)
		p.hasPorts, p.hasTCP = true, true
	case 17:
		l4 = make([]byte, 8+payload)
		binary.BigEndian.PutUint16(l4[0:], p.sport)
		binary.BigEndian.PutUint16(l4[2:], p.dport)
		binary.BigEndian.PutUint16(l4[4:], uint16(len(l4)))
		p.hasPorts = true
	default:
		l4 = append([]byte{8, 0, 0, 0, 0, 1, 0, 1}, make([]byte, payload)...)
	}

	eth := make([]byte, 14)
	var ip []byte
	if p.v6 {
		binary.BigEndian.PutUint16(eth[12:], 0x86dd)
		ip = make([]byte, 40)
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:], uint16(len(l4)))
		ip[6] = map[uint8]uint8{6: 6, 17: 17, 1: 58}[p.proto]
		if p.proto == 1 {
			p.proto = 58
		}
		ip[7] = 64
		s, d := p.src.As16(), p.dst.As16()
		copy(ip[8:], s[:])
		copy(ip[24:], d[:])
		p.length = uint16(40 + len(l4))
	} else {
		binary.BigEndian.PutUint16(eth[12:], 0x0800)
		ip = make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)))
		var frag uint16
		switch r.Intn(6) {
		case 0:
			frag = 0x2000 // MF, first fragment: ports still present
		case 1:
			frag = 0x0010 // later fragment: no L4 header
			p.hasPorts, p.hasTCP = false, false
		}
		p.frag = frag != 0
		binary.BigEndian.PutUint16(ip[6:], frag)
		ip[8] = 64
		ip[9] = p.proto
		s, d := p.src.As4(), p.dst.As4()
		copy(ip[12:], s[:])
		copy(ip[16:], d[:])
		p.length = uint16(20 + len(l4))
	}
	p.data = append(append(eth, ip...), l4...)
	return p
}

func inRanges(rs []*apiv1.PortRange, v uint16) bool {
	if len(rs) == 0 {
		return true
	}
	for _, r := range rs {
		if uint32(v) >= r.From && uint32(v) <= r.To {
			return true
		}
	}
	return false
}

// referenceMatch applies the rule semantics directly to the unprocessed rule.
func referenceMatch(pr *apiv1.Rule, p testPkt) bool {
	dst := netip.MustParsePrefix(pr.DstPrefix)
	if dst.Addr().Is4() == p.v6 || !dst.Contains(p.dst) {
		return false
	}
	if len(pr.Protocols) > 0 && !slices.Contains(pr.Protocols, uint32(p.proto)) {
		return false
	}
	if pr.Fragment != nil && *pr.Fragment != p.frag {
		return false
	}
	if l := pr.PktLen; l != nil && (l.From != 0 || l.To != 0) && (uint32(p.length) < l.From || uint32(p.length) > l.To) {
		return false
	}
	if pr.TcpFlagsMask != 0 && (!p.hasTCP || uint32(p.tcpFlags)&pr.TcpFlagsMask != pr.TcpFlagsValue) {
		return false
	}
	if len(pr.SrcPorts)+len(pr.DstPorts) > 0 && (!p.hasPorts || !inRanges(pr.SrcPorts, p.sport) || !inRanges(pr.DstPorts, p.dport)) {
		return false
	}
	if len(pr.SrcPrefixes) == 0 {
		return true
	}
	for _, s := range pr.SrcPrefixes {
		if netip.MustParsePrefix(s).Contains(p.src) {
			return true
		}
	}
	return false
}

// ruleCase names the XDP path a rule takes, so the test can insist that each
// path was exercised by both matches and near misses.
func ruleCase(pr *apiv1.Rule) string {
	if len(pr.SrcPrefixes) == 0 {
		return "no sources"
	}
	if netip.MustParsePrefix(pr.DstPrefix).Addr().Is6() {
		return "v6 sources"
	}
	for _, s := range pr.SrcPrefixes {
		if netip.MustParsePrefix(s).Bits() != netip.MustParsePrefix(pr.SrcPrefixes[0]).Bits() {
			return "v4 mixed lengths"
		}
	}
	return "v4 same length"
}

// srcNearMiss reports whether only the source prefixes reject p, with p's
// source inside their span, so XDP gets past the span check.
func srcNearMiss(pr *apiv1.Rule, p testPkt) bool {
	if len(pr.SrcPrefixes) == 0 || referenceMatch(pr, p) {
		return false
	}
	noSrc := proto.Clone(pr).(*apiv1.Rule)
	noSrc.SrcPrefixes = nil
	if !referenceMatch(noSrc, p) {
		return false
	}
	lo, hi := false, false
	for _, s := range pr.SrcPrefixes {
		pf := netip.MustParsePrefix(s).Masked()
		lo = lo || pf.Addr().Compare(p.src) <= 0
		hi = hi || pf.Addr().Compare(p.src) > 0 || pf.Contains(p.src)
	}
	return lo && hi
}

func TestScrubRuleMatcher(t *testing.T) {
	l := ebpf.NewLoader(ebpf.LoaderConfig{Mode: ebpf.ModeScrub, Interface: "lo"})
	if err := l.Load(); err != nil {
		t.Fatalf("load eBPF: %v", err)
	}
	defer l.Close()
	m := l.GetMaps()
	// Lift the per-source ICMP/UDP limits so only rules can drop.
	for _, key := range []uint32{0, 2} {
		if err := m.ConfigMap.Put(key, uint32(math.MaxUint32)); err != nil {
			t.Fatal(err)
		}
	}
	prog := l.Program("xdp_scrub")
	e := newRuleEngine(m)

	rng := rand.New(rand.NewSource(1))
	var ids []string
	checked, matched := 0, 0
	matches, nearMisses := map[string]int{}, map[string]int{}
	for round := range 40 {
		var rules []*apiv1.Rule
		for i := range 4 + rng.Intn(20) {
			rules = append(rules, randRule(rng, round*100+i))
		}
		if _, err := e.Apply(&apiv1.RuleSetDelta{Remove: ids, Upsert: rules}, time.Now()); err != nil {
			t.Fatalf("round %d: apply: %v", round, err)
		}
		ids = ids[:0]
		for _, r := range rules {
			ids = append(ids, r.Id)
		}
		for range 1500 {
			p := buildPkt(rng)
			ret, err := prog.Run(&cebpf.RunOptions{Data: p.data})
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			want := false
			for _, r := range rules {
				if referenceMatch(r, p) {
					want = true
					matches[ruleCase(r)]++
				} else if srcNearMiss(r, p) {
					nearMisses[ruleCase(r)]++
				}
			}
			if got := ret == 1; got != want {
				t.Fatalf("round %d: packet %+v: XDP_DROP=%v, reference match=%v\nrules: %v", round, p, got, want, rules)
			}
			checked++
			if want {
				matched++
			}
		}
	}
	t.Logf("%d packets checked, %d matched a rule; matches %v, source near misses %v", checked, matched, matches, nearMisses)
	if matched == 0 || matched == checked {
		t.Fatalf("%d of %d packets matched; the generator must produce both outcomes", matched, checked)
	}
	for _, c := range []string{"no sources", "v4 same length", "v4 mixed lengths", "v6 sources"} {
		if matches[c] == 0 {
			t.Errorf("no packet matched a rule with %s", c)
		}
		if c != "no sources" && nearMisses[c] == 0 {
			t.Errorf("no packet reached the source check of a rule with %s and missed", c)
		}
	}
}
