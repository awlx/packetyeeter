package collector

import (
	"fmt"
	"net"
	"sync"
	"testing"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/collector/ebpf"

	"github.com/sirupsen/logrus"
)

// executeCommand mutates allowedNets on the command-stream goroutine while
// checkAllowlist reads it from the polling/perf/SPOE goroutines. Run with
// -race: this fails when allowedNets is unsynchronized.
func TestAllowlistCommandsConcurrentWithChecks(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(nil)
	logger.SetLevel(logrus.PanicLevel)
	c := &Collector{Logger: logger, Maps: &ebpf.Maps{}}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range 500 {
			ip := net.ParseIP(fmt.Sprintf("198.51.100.%d", i%256)).To4()
			c.executeCommand(&apiv1.Command{Type: apiv1.CommandType_COMMAND_ALLOWLIST_IP, Ip: ip})
			c.executeCommand(&apiv1.Command{Type: apiv1.CommandType_COMMAND_REMOVE_ALLOWLIST_IP, Ip: ip})
		}
	}()
	go func() {
		defer wg.Done()
		probe := net.ParseIP("198.51.100.7")
		for range 5000 {
			c.checkAllowlist(probe)
		}
	}()
	wg.Wait()
}
