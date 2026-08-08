package collector

import (
	"net"
	"testing"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/collector/ebpf"
)

// emitFloodSignal must not retain the caller's IP backing array. The rate-map
// iterators reuse a single [16]byte key across iterations, and queued signals
// are marshaled asynchronously off signalQueue, so a stored alias would ship
// every IPv6 flood signal with the last-iterated source IP.
func TestEmitFloodSignalDoesNotAliasKey(t *testing.T) {
	c := &Collector{signalQueue: make(chan *apiv1.Signal, 8)}

	// Use non-loopback ULA (fd00::/8) addresses; ::1 would be allowlisted.
	var key [16]byte
	key[0] = 0xfd
	key[15] = 1
	c.emitFloodSignal(net.IP(key[:]), 2000, ebpf.ICMPRate{Count: 2000},
		apiv1.SignalType_SIGNAL_ICMP_FLOOD, "icmp6")
	key[15] = 2 // iter.Next overwrites the shared backing array in place
	c.emitFloodSignal(net.IP(key[:]), 2000, ebpf.ICMPRate{Count: 2000},
		apiv1.SignalType_SIGNAL_ICMP_FLOOD, "icmp6")

	s1 := <-c.signalQueue
	s2 := <-c.signalQueue
	got1, got2 := net.IP(s1.Ip).String(), net.IP(s2.Ip).String()
	if got1 == got2 {
		t.Fatalf("both signals carry IP %q: key buffer aliased across async handoff", got1)
	}
	if got1 != "fd00::1" || got2 != "fd00::2" {
		t.Fatalf("signal IPs = %q,%q; want fd00::1,fd00::2", got1, got2)
	}
	// The id is formatted post-gate from the copied address; it must reflect
	// each signal's own source, not the last-iterated key.
	if s1.Id != "icmp6-fd00::1" || s2.Id != "icmp6-fd00::2" {
		t.Fatalf("signal Ids = %q,%q; want icmp6-fd00::1,icmp6-fd00::2", s1.Id, s2.Id)
	}
}
