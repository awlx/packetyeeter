package collector

import (
	"os"
	"testing"

	"PacketYeeter/pkg/collector/ebpf"

	"github.com/sirupsen/logrus"
)

// TestSendBadFlagsAlertsNilSafety ensures sendBadFlagsAlerts tolerates a
// collector with no eBPF maps loaded (e.g. before the poller starts, or in
// dry-run/test harnesses that don't load the kernel program) instead of
// panicking on a nil map handle.
func TestSendBadFlagsAlertsNilSafety(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(os.Stderr)

	c := &Collector{Logger: logger}
	c.sendBadFlagsAlerts() // Maps == nil

	c.Maps = &ebpf.Maps{}
	c.sendBadFlagsAlerts() // Maps set, but BadFlags/BadFlagsV6 handles nil
}
