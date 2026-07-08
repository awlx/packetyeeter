package collector

import (
	"os"
	"testing"

	"PacketYeeter/pkg/collector/ebpf"

	"github.com/sirupsen/logrus"
)

// TestStartIncidentReaderNilSafety ensures startIncidentReader fails
// gracefully (returns an error, doesn't panic) when no eBPF maps are
// loaded, e.g. before Start() runs or in test harnesses that don't load
// the kernel program.
func TestStartIncidentReaderNilSafety(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(os.Stderr)

	c := &Collector{Logger: logger}
	if err := c.startIncidentReader(); err == nil {
		t.Error("expected error when Maps is nil, got nil")
	}

	c.Maps = &ebpf.Maps{}
	if err := c.startIncidentReader(); err == nil {
		t.Error("expected error when Maps.Incidents is nil, got nil")
	}
}

// TestProcessIncidentEventNilSafety ensures processIncidentEvent tolerates
// malformed/short input without panicking.
func TestProcessIncidentEventNilSafety(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(os.Stderr)

	c := &Collector{Logger: logger}
	c.processIncidentEvent(nil)
	c.processIncidentEvent([]byte{1, 2, 3}) // too short to decode
}
