// Command xdp_veth_udpflood is a throwaway high-rate UDP sender used only by
// scripts/xdp_veth_test.sh. nping cannot auto-select an IPv6 source inside the
// test netns, so this uses the kernel UDP stack (proper source/route/ND) to
// blast an IPv4 or IPv6 target for a fixed duration.
//
// Usage: xdp_veth_udpflood <udp4|udp6> <host> <port> <seconds>
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: xdp_veth_udpflood <udp4|udp6> <host> <port> <seconds>")
		os.Exit(2)
	}
	network, host, port := os.Args[1], os.Args[2], os.Args[3]
	secs, err := strconv.Atoi(os.Args[4])
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad seconds:", err)
		os.Exit(2)
	}

	conn, err := net.Dial(network, net.JoinHostPort(host, port))
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}
	defer conn.Close()

	payload := make([]byte, 64)
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	var sent uint64
	for time.Now().Before(deadline) {
		// Send in bursts so the time check isn't the bottleneck.
		for range 2000 {
			if _, err := conn.Write(payload); err == nil {
				sent++
			}
		}
	}
	fmt.Fprintf(os.Stderr, "udpflood %s %s:%s sent=%d\n", network, host, port, sent)
}
