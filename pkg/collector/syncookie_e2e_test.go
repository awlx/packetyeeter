//go:build linux && e2e_ebpf

// Runs xdp_scrub through BPF_PROG_TEST_RUN to check the SYN cookie challenge
// and verification paths. Requires root, Linux 6.0+ and `make bpf`:
//
//	sudo -E go test -tags e2e_ebpf -run TestScrubSynCookie -v ./pkg/collector/
package collector

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	cebpf "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"PacketYeeter/pkg/collector/ebpf"
)

// xdpDrop, xdpPass and the tcp* flags are in xdp_verdict_e2e_test.go.
const xdpTX = 3

// A typical Linux SYN's options: MSS, SACK permitted, timestamps, window scale.
var synOptions = []byte{2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7}

var (
	scClientMAC = []byte{0x02, 0, 0, 0, 0, 1}
	scNodeMAC   = []byte{0x02, 0, 0, 0, 0, 2}
)

type tcpSeg struct {
	src, dst     netip.Addr
	sport, dport uint16
	seq, ack     uint32
	flags        uint8
	options      []byte
	payload      []byte
	ipOptions    []byte // IPv4 only
	destOpts     bool   // IPv6: put a Destination Options header before TCP
}

func csum(b []byte, initial uint32) uint16 {
	sum := initial
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func pseudoSum(src, dst netip.Addr, l4Len int) uint32 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
	}
	add(src.AsSlice())
	add(dst.AsSlice())
	return sum + 6 + uint32(l4Len)
}

func (s tcpSeg) frame() []byte {
	tcp := make([]byte, 20+len(s.options))
	binary.BigEndian.PutUint16(tcp[0:], s.sport)
	binary.BigEndian.PutUint16(tcp[2:], s.dport)
	binary.BigEndian.PutUint32(tcp[4:], s.seq)
	binary.BigEndian.PutUint32(tcp[8:], s.ack)
	tcp[12] = byte(len(tcp)/4) << 4
	tcp[13] = s.flags
	binary.BigEndian.PutUint16(tcp[14:], 64240)
	copy(tcp[20:], s.options)
	tcp = append(tcp, s.payload...)
	binary.BigEndian.PutUint16(tcp[16:], csum(tcp, pseudoSum(s.src, s.dst, len(tcp))))

	eth := append(append(append([]byte{}, scNodeMAC...), scClientMAC...), 0, 0)
	if s.src.Is4() {
		binary.BigEndian.PutUint16(eth[12:], 0x0800)
		ip := make([]byte, 20+len(s.ipOptions))
		ip[0] = 0x40 | byte(len(ip)/4)
		binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)+len(tcp)))
		ip[6] = 0x40
		ip[8], ip[9] = 64, 6
		copy(ip[12:], s.src.AsSlice())
		copy(ip[16:], s.dst.AsSlice())
		copy(ip[20:], s.ipOptions)
		binary.BigEndian.PutUint16(ip[10:], csum(ip, 0))
		return append(append(eth, ip...), tcp...)
	}
	binary.BigEndian.PutUint16(eth[12:], 0x86dd)
	ip := make([]byte, 40)
	ip[0] = 0x60
	ip[6], ip[7] = 6, 64
	copy(ip[8:], s.src.AsSlice())
	copy(ip[24:], s.dst.AsSlice())
	if s.destOpts {
		ip[6] = 60
		tcp = append([]byte{6, 0, 1, 4, 0, 0, 0, 0}, tcp...) // PadN
	}
	binary.BigEndian.PutUint16(ip[4:], uint16(len(tcp)))
	return append(append(eth, ip...), tcp...)
}

// parseReply checks a frame xdp_scrub transmitted back and returns its TCP
// header; it fails the test on wrong addressing, lengths or checksums.
func parseReply(t *testing.T, in tcpSeg, out []byte) (seq, ack uint32, flags uint8) {
	t.Helper()
	if !bytes.Equal(out[0:6], scClientMAC) || !bytes.Equal(out[6:12], scNodeMAC) {
		t.Fatalf("MACs not swapped: % x", out[:12])
	}
	var tcp []byte
	if in.src.Is4() {
		ip := out[14:34]
		if ip[0] != 0x45 || ip[9] != 6 || binary.BigEndian.Uint16(ip[2:]) != 40 || len(out) != 54 {
			t.Fatalf("bad IPv4 reply header % x (frame %d bytes)", ip, len(out))
		}
		if csum(ip, 0) != 0 {
			t.Fatalf("bad IPv4 header checksum")
		}
		if netip.AddrFrom4([4]byte(ip[12:16])) != in.dst || netip.AddrFrom4([4]byte(ip[16:20])) != in.src {
			t.Fatalf("addresses not swapped: % x", ip[12:20])
		}
		tcp = out[34:54]
	} else {
		ip := out[14:54]
		if ip[0]>>4 != 6 || ip[6] != 6 || binary.BigEndian.Uint16(ip[4:]) != 20 || len(out) != 74 {
			t.Fatalf("bad IPv6 reply header % x (frame %d bytes)", ip, len(out))
		}
		if netip.AddrFrom16([16]byte(ip[8:24])) != in.dst || netip.AddrFrom16([16]byte(ip[24:40])) != in.src {
			t.Fatalf("addresses not swapped")
		}
		tcp = out[54:74]
	}
	if csum(tcp, pseudoSum(in.dst, in.src, len(tcp))) != 0 {
		t.Fatalf("bad TCP checksum")
	}
	if binary.BigEndian.Uint16(tcp[0:]) != in.dport || binary.BigEndian.Uint16(tcp[2:]) != in.sport {
		t.Fatalf("ports not swapped")
	}
	if tcp[12] != 5<<4 {
		t.Fatalf("data offset %d, want 5", tcp[12]>>4)
	}
	return binary.BigEndian.Uint32(tcp[4:]), binary.BigEndian.Uint32(tcp[8:]), tcp[13]
}

func loadSynCookieScrub(t *testing.T, cfg ebpf.SynCookieConfig) (*ebpf.Maps, *cebpf.Program) {
	t.Helper()
	requireRoot(t)
	l := ebpf.NewLoader(ebpf.LoaderConfig{Mode: ebpf.ModeScrub, SynCookies: true})
	if err := l.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(l.Close)
	m := l.GetMaps()
	if cfg.TTL == 0 {
		cfg.TTL = time.Minute
	}
	if err := m.SetSynCookies(cfg); err != nil {
		t.Fatal(err)
	}
	return m, l.Program("xdp_scrub")
}

func run(t *testing.T, prog *cebpf.Program, frame []byte) (uint32, []byte) {
	t.Helper()
	out := make([]byte, len(frame)+256)
	ret, err := prog.Run(&cebpf.RunOptions{Data: frame, DataOut: out})
	if err != nil {
		t.Fatalf("prog run: %v", err)
	}
	return ret, out
}

// runTX runs a frame that must be answered and returns the reply.
func runTX(t *testing.T, prog *cebpf.Program, s tcpSeg) (seq, ack uint32, flags uint8) {
	t.Helper()
	frame := s.frame()
	out := make([]byte, len(frame))
	opts := &cebpf.RunOptions{Data: frame, DataOut: out}
	ret, err := prog.Run(opts)
	if err != nil {
		t.Fatalf("prog run: %v", err)
	}
	if ret != xdpTX {
		t.Fatalf("verdict %d, want XDP_TX", ret)
	}
	return parseReply(t, s, opts.DataOut)
}

func scEvents(t *testing.T, m *ebpf.Maps, v6 bool) map[string]uint64 {
	t.Helper()
	st, err := m.ReadSynCookieStats()
	if err != nil {
		t.Fatal(err)
	}
	f := 0
	if v6 {
		f = 1
	}
	out := map[string]uint64{}
	for i, name := range ebpf.SynCookieEventNames {
		if st[f][i] != 0 {
			out[name] = st[f][i]
		}
	}
	return out
}

func wantEvents(t *testing.T, m *ebpf.Maps, v6 bool, want map[string]uint64) {
	t.Helper()
	got := scEvents(t, m, v6)
	if len(got) != len(want) {
		t.Fatalf("events %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("events %v, want %v", got, want)
		}
	}
}

func verified(t *testing.T, m *ebpf.Maps, a netip.Addr) bool {
	t.Helper()
	var v uint64
	var err error
	if a.Is4() {
		err = m.SynCookieVerifiedV4.Lookup(a.As4(), &v)
	} else {
		err = m.SynCookieVerifiedV6.Lookup(a.As16(), &v)
	}
	return err == nil
}

type scFamily struct {
	name             string
	client, attacker netip.Addr
	dst              netip.Addr
}

var scFamilies = []scFamily{
	{"ipv4", netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("192.0.2.10")},
	{"ipv6", netip.MustParseAddr("2001:db8:1::7"), netip.MustParseAddr("2001:db8:666::9"), netip.MustParseAddr("2001:db8:2::10")},
}

func TestScrubSynCookieOOS(t *testing.T) {
	for _, f := range scFamilies {
		t.Run(f.name, func(t *testing.T) {
			m, prog := loadSynCookieScrub(t, ebpf.SynCookieConfig{Mode: ebpf.SynCookiesOn, Style: ebpf.SynCookieStyleOOS})
			v6 := f.client.Is6()
			syn := tcpSeg{src: f.client, dst: f.dst, sport: 40001, dport: 443, seq: 1000, flags: tcpSYN, options: synOptions}

			_, ack, flags := runTX(t, prog, syn)
			if flags != tcpSYN|tcpACK {
				t.Fatalf("challenge flags %#x, want SYN|ACK", flags)
			}
			if ack == syn.seq+1 {
				t.Fatalf("challenge acknowledges the client's SYN; the client would complete the handshake")
			}
			// Same 4-tuple, same cookie: it does not depend on the ISN.
			syn2 := syn
			syn2.seq = 77777
			if _, ack2, _ := runTX(t, prog, syn2); ack2 != ack {
				t.Fatalf("cookie changed with the ISN: %d vs %d", ack, ack2)
			}
			wantEvents(t, m, v6, map[string]uint64{"challenge": 2})

			// A RST with a wrong sequence number is forwarded, not trusted.
			// (ack+1..ack+3 would pass: the low bits encode the MSS.)
			bad := tcpSeg{src: f.client, dst: f.dst, sport: 40001, dport: 443, seq: ack + 0x1000, flags: tcpRST}
			if ret, _ := run(t, prog, bad.frame()); ret == xdpDrop || ret == xdpTX {
				t.Fatalf("bad RST verdict %d, want it forwarded", ret)
			}
			// Another port's cookie differs.
			other := tcpSeg{src: f.client, dst: f.dst, sport: 40002, dport: 443, seq: ack, flags: tcpRST}
			if ret, _ := run(t, prog, other.frame()); ret == xdpDrop || ret == xdpTX {
				t.Fatalf("RST on another port verdict %d, want it forwarded", ret)
			}
			if verified(t, m, f.client) {
				t.Fatal("source verified by a bad RST")
			}
			wantEvents(t, m, v6, map[string]uint64{"challenge": 2, "invalid": 2})

			// What Linux, BSD and Windows send for an unacceptable SYN-ACK in
			// SYN-SENT: RST, seq = the SYN-ACK's ack.
			rst := tcpSeg{src: f.client, dst: f.dst, sport: 40001, dport: 443, seq: ack, flags: tcpRST}
			if ret, _ := run(t, prog, rst.frame()); ret != xdpDrop {
				t.Fatalf("valid RST verdict %d, want XDP_DROP", ret)
			}
			if !verified(t, m, f.client) {
				t.Fatal("source not verified by a valid RST")
			}
			// The retransmitted SYN passes, and so does one on a new port.
			for _, port := range []uint16{40001, 40009} {
				s := syn
				s.sport = port
				if ret, _ := run(t, prog, s.frame()); ret == xdpDrop || ret == xdpTX {
					t.Fatalf("SYN from a verified source verdict %d, want it forwarded", ret)
				}
			}
			wantEvents(t, m, v6, map[string]uint64{"challenge": 2, "invalid": 2, "valid": 1, "passed": 2})

			// Another source is still challenged.
			spoofed := syn
			spoofed.src = f.attacker
			if _, _, flags := runTX(t, prog, spoofed); flags != tcpSYN|tcpACK {
				t.Fatalf("spoofed SYN answered with %#x", flags)
			}
		})
	}
}

func TestScrubSynCookieReset(t *testing.T) {
	for _, f := range scFamilies {
		t.Run(f.name, func(t *testing.T) {
			m, prog := loadSynCookieScrub(t, ebpf.SynCookieConfig{Mode: ebpf.SynCookiesOn, Style: ebpf.SynCookieStyleReset})
			v6 := f.client.Is6()
			syn := tcpSeg{src: f.client, dst: f.dst, sport: 40001, dport: 443, seq: 1000, flags: tcpSYN, options: synOptions}
			cookie, ack, flags := runTX(t, prog, syn)
			if flags != tcpSYN|tcpACK || ack != syn.seq+1 {
				t.Fatalf("challenge flags %#x ack %d, want SYN|ACK acking %d", flags, ack, syn.seq+1)
			}

			// A data segment is not checked, and a wrong cookie is forwarded.
			data := tcpSeg{src: f.client, dst: f.dst, sport: 40001, dport: 443, seq: 1001, ack: cookie + 1, flags: tcpACK | tcpPSH, payload: []byte("GET / HTTP/1.1\r\n\r\n")}
			if ret, _ := run(t, prog, data.frame()); ret == xdpDrop || ret == xdpTX {
				t.Fatalf("data segment verdict %d, want it forwarded", ret)
			}
			bad := tcpSeg{src: f.client, dst: f.dst, sport: 40001, dport: 443, seq: 1001, ack: cookie + 1 + 0x1000, flags: tcpACK}
			if ret, _ := run(t, prog, bad.frame()); ret == xdpDrop || ret == xdpTX {
				t.Fatalf("bad ACK verdict %d, want it forwarded", ret)
			}
			wantEvents(t, m, v6, map[string]uint64{"challenge": 1, "invalid": 1})

			ackSeg := tcpSeg{src: f.client, dst: f.dst, sport: 40001, dport: 443, seq: 1001, ack: cookie + 1, flags: tcpACK,
				options: []byte{1, 1, 8, 10, 0, 0, 0, 2, 0, 0, 0, 0}}
			rseq, _, rflags := runTX(t, prog, ackSeg)
			if rflags != tcpRST || rseq != cookie+1 {
				t.Fatalf("answer to a valid ACK: flags %#x seq %d, want RST seq %d", rflags, rseq, cookie+1)
			}
			if !verified(t, m, f.client) {
				t.Fatal("source not verified by a valid ACK")
			}
			s := syn
			s.sport = 40002
			if ret, _ := run(t, prog, s.frame()); ret == xdpDrop || ret == xdpTX {
				t.Fatalf("SYN from a verified source verdict %d, want it forwarded", ret)
			}
			wantEvents(t, m, v6, map[string]uint64{"challenge": 1, "invalid": 1, "valid": 1, "passed": 1})
		})
	}
}

func TestScrubSynCookieDryRun(t *testing.T) {
	m, prog := loadSynCookieScrub(t, ebpf.SynCookieConfig{Mode: ebpf.SynCookiesOn})
	if err := m.SetMonitorMode(true); err != nil {
		t.Fatal(err)
	}
	for _, f := range scFamilies {
		syn := tcpSeg{src: f.client, dst: f.dst, sport: 40001, dport: 443, seq: 1000, flags: tcpSYN}
		if ret, _ := run(t, prog, syn.frame()); ret == xdpDrop || ret == xdpTX {
			t.Fatalf("%s: dry-run verdict %d, want the SYN forwarded", f.name, ret)
		}
		unsupported := syn
		if f.client.Is4() {
			unsupported.ipOptions = []byte{1, 1, 1, 0}
		} else {
			unsupported.destOpts = true
		}
		if ret, _ := run(t, prog, unsupported.frame()); ret == xdpDrop || ret == xdpTX {
			t.Fatalf("%s: dry-run verdict %d for a SYN with options, want it forwarded", f.name, ret)
		}
		wantEvents(t, m, f.client.Is6(), map[string]uint64{"dry_run": 2})
	}
}

func TestScrubSynCookieUnsupported(t *testing.T) {
	m, prog := loadSynCookieScrub(t, ebpf.SynCookieConfig{Mode: ebpf.SynCookiesOn})
	for _, f := range scFamilies {
		syn := tcpSeg{src: f.client, dst: f.dst, sport: 40001, dport: 443, seq: 1000, flags: tcpSYN}
		if f.client.Is4() {
			syn.ipOptions = []byte{1, 1, 1, 0} // NOPs
		} else {
			syn.destOpts = true
		}
		if ret, _ := run(t, prog, syn.frame()); ret != xdpDrop {
			t.Fatalf("%s: SYN that cannot be answered: verdict %d, want XDP_DROP", f.name, ret)
		}
		// Other segments with the same headers are left alone.
		ack := syn
		ack.flags = tcpACK
		if ret, _ := run(t, prog, ack.frame()); ret == xdpDrop || ret == xdpTX {
			t.Fatalf("%s: ACK with extra headers verdict %d, want it forwarded", f.name, ret)
		}
		wantEvents(t, m, f.client.Is6(), map[string]uint64{"unsupported": 1})
	}
}

func TestScrubSynCookieAllowlistAndTTL(t *testing.T) {
	m, prog := loadSynCookieScrub(t, ebpf.SynCookieConfig{Mode: ebpf.SynCookiesOn, TTL: time.Second})
	f := scFamilies[0]
	_, allowed, _ := net.ParseCIDR("198.51.100.0/24")
	if err := m.SyncAllowlist([]*net.IPNet{allowed}); err != nil {
		t.Fatal(err)
	}
	syn := tcpSeg{src: f.client, dst: f.dst, sport: 40001, dport: 443, seq: 1000, flags: tcpSYN}
	if ret, _ := run(t, prog, syn.frame()); ret == xdpDrop || ret == xdpTX {
		t.Fatalf("allowlisted SYN verdict %d, want it forwarded", ret)
	}
	if err := m.RemoveAllowlistEntry(allowed); err != nil {
		t.Fatal(err)
	}

	_, ack, _ := runTX(t, prog, syn)
	rst := tcpSeg{src: f.client, dst: f.dst, sport: 40001, dport: 443, seq: ack, flags: tcpRST}
	if ret, _ := run(t, prog, rst.frame()); ret != xdpDrop {
		t.Fatalf("valid RST verdict %d", ret)
	}
	if ret, _ := run(t, prog, syn.frame()); ret == xdpTX {
		t.Fatal("verified source challenged")
	}
	time.Sleep(1100 * time.Millisecond)
	if _, _, flags := runTX(t, prog, syn); flags != tcpSYN|tcpACK {
		t.Fatal("source not challenged again after the TTL")
	}
}

// pinCPU keeps the test on one CPU, so the per-CPU SYN rate sees every SYN.
func pinCPU(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)
	var set unix.CPUSet
	set.Set(0)
	if err := unix.SchedSetaffinity(0, &set); err != nil {
		t.Fatal(err)
	}
}

func scSlot(a netip.Addr) uint32 {
	var w [4]uint32
	b := a.As16()
	if a.Is4() {
		w[0] = binary.LittleEndian.Uint32(a.AsSlice())
	} else {
		for i := range w {
			w[i] = binary.LittleEndian.Uint32(b[4*i:])
		}
	}
	return ((w[0] ^ w[1] ^ w[2] ^ w[3]) * 0x9E3779B1) >> (32 - 13)
}

func TestScrubSynCookieAuto(t *testing.T) {
	pinCPU(t)
	cpus, err := cebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	const perCPU = 3
	m, prog := loadSynCookieScrub(t, ebpf.SynCookieConfig{Mode: ebpf.SynCookiesAuto, SynPPS: uint32(perCPU * cpus)})
	for _, f := range scFamilies {
		quiet := f.dst.Next()
		if scSlot(quiet) == scSlot(f.dst) {
			t.Fatalf("%v and %v share a slot", quiet, f.dst)
		}
		// The time window is one second; stay inside one.
		for time.Now().Nanosecond() > 500e6 {
			time.Sleep(10 * time.Millisecond)
		}
		syn := tcpSeg{src: f.attacker, dst: f.dst, sport: 1, dport: 80, seq: 1, flags: tcpSYN}
		for i := range perCPU {
			syn.sport = uint16(1000 + i)
			if ret, _ := run(t, prog, syn.frame()); ret == xdpTX || ret == xdpDrop {
				t.Fatalf("%s: SYN %d under the threshold verdict %d", f.name, i, ret)
			}
		}
		syn.sport = 2000
		runTX(t, prog, syn)
		// Answers count only while the destination is challenged.
		client := tcpSeg{src: f.client, dst: f.dst, sport: 3000, dport: 80, seq: 1, flags: tcpSYN}
		runTX(t, prog, client)
		q := client
		q.dst = quiet
		if ret, _ := run(t, prog, q.frame()); ret == xdpTX {
			t.Fatalf("%s: quiet destination challenged", f.name)
		}
		wantEvents(t, m, f.client.Is6(), map[string]uint64{"challenge": 2, "activated": 1})
	}
}
