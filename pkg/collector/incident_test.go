package collector

import (
	"bytes"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"PacketYeeter/pkg/collector/ebpf"
	"PacketYeeter/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus/testutil"
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

func TestRecordPerfLostSamples(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(&bytes.Buffer{})
	c := &Collector{Logger: logger}

	before := testutil.ToFloat64(metrics.PerfLostSamples.WithLabelValues("incidents"))
	c.recordPerfLostSamples("incidents", 7)
	after := testutil.ToFloat64(metrics.PerfLostSamples.WithLabelValues("incidents"))
	if got := after - before; got != 7 {
		t.Fatalf("lost-sample metric increment = %v, want 7", got)
	}
}

func TestCollectorMetricsExposePerfLostSamples(t *testing.T) {
	c := &Collector{Config: Config{MetricsAddr: "127.0.0.1:0"}}
	metrics.PerfLostSamples.WithLabelValues("incidents").Add(0)
	server := c.startCollectorMetricsServer()
	req := httptest.NewRequest("GET", "/metrics", nil)
	resp := httptest.NewRecorder()
	server.Handler.ServeHTTP(resp, req)

	if resp.Code != 200 {
		t.Fatalf("metrics status = %d, want 200", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "packetyeeter_perf_lost_samples_total") {
		t.Fatal("collector metrics do not expose perf lost samples")
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
