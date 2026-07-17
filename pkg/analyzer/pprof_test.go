package analyzer

import "testing"

// The pprof diagnostic server must resist slowloris (bounded read/idle/header)
// like the metrics and inspector servers, but must NOT set a WriteTimeout:
// /debug/pprof/profile and /trace stream for a client-specified duration and a
// WriteTimeout would truncate them.
func TestNewPprofServerHardenedButAllowsProfiling(t *testing.T) {
	s := newPprofServer("127.0.0.1:0")

	if s.ReadHeaderTimeout <= 0 {
		t.Error("ReadHeaderTimeout must be set to resist slowloris header trickling")
	}
	if s.ReadTimeout <= 0 {
		t.Error("ReadTimeout must be set")
	}
	if s.IdleTimeout <= 0 {
		t.Error("IdleTimeout must be set")
	}
	if s.MaxHeaderBytes <= 0 {
		t.Error("MaxHeaderBytes must be bounded")
	}
	if s.WriteTimeout != 0 {
		t.Errorf("WriteTimeout must stay 0 so profile/trace are not truncated, got %v", s.WriteTimeout)
	}
}
