package ebpf

import (
	"testing"
	"time"
)

func TestParseSynCookieFlags(t *testing.T) {
	for in, want := range map[string]SynCookieMode{"": SynCookiesOff, "off": SynCookiesOff, "auto": SynCookiesAuto, "on": SynCookiesOn} {
		if got, err := ParseSynCookieMode(in); err != nil || got != want {
			t.Errorf("ParseSynCookieMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseSynCookieMode("yes"); err == nil {
		t.Error("ParseSynCookieMode(yes) succeeded")
	}
	for in, want := range map[string]SynCookieStyle{"": SynCookieStyleOOS, "oos": SynCookieStyleOOS, "reset": SynCookieStyleReset} {
		if got, err := ParseSynCookieStyle(in); err != nil || got != want {
			t.Errorf("ParseSynCookieStyle(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseSynCookieStyle("proxy"); err == nil {
		t.Error("ParseSynCookieStyle(proxy) succeeded")
	}
}

func TestSynCookieConfigValues(t *testing.T) {
	got, err := synCookieConfigValues(SynCookieConfig{Mode: SynCookiesAuto, Style: SynCookieStyleReset, SynPPS: 10000, TTL: 90 * time.Second, MaxPPS: 20000}, 8)
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint32]uint32{configKeySCMode: scModeAuto, configKeySCSynPPS: 1250, configKeySCTTL: 90, configKeySCStyle: scStyleReset, configKeySCMaxPPS: 2500}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("config_map[%d] = %d, want %d", k, got[k], v)
		}
	}
	// A per-CPU share never rounds down to 0.
	if got, err := synCookieConfigValues(SynCookieConfig{Mode: SynCookiesAuto, SynPPS: 3, TTL: time.Minute}, 8); err != nil || got[configKeySCSynPPS] != 1 {
		t.Errorf("3 pps over 8 CPUs: %d, %v; want 1", got[configKeySCSynPPS], err)
	}
	if got, err := synCookieConfigValues(SynCookieConfig{Mode: SynCookiesOn, TTL: time.Minute}, 8); err != nil ||
		got[configKeySCMode] != scModeOn || got[configKeySCStyle] != scStyleOOS || got[configKeySCMaxPPS] != 0 {
		t.Errorf("on: %v, %v", got, err)
	}
	for name, cfg := range map[string]SynCookieConfig{
		"off":        {Mode: SynCookiesOff, TTL: time.Minute},
		"auto 0 pps": {Mode: SynCookiesAuto, TTL: time.Minute},
		"ttl < 1s":   {Mode: SynCookiesOn, TTL: time.Millisecond},
		"bad style":  {Mode: SynCookiesOn, Style: "proxy", TTL: time.Minute},
	} {
		if _, err := synCookieConfigValues(cfg, 8); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSumSynCookieStats(t *testing.T) {
	n := len(SynCookieEventNames)
	perIndex := make([][]uint64, 2*n)
	for i := range perIndex {
		perIndex[i] = []uint64{1, uint64(i)}
	}
	s := sumSynCookieStats(perIndex)
	if s[0][0] != 1 || s[0][2] != 3 || s[1][0] != 1+uint64(n) || s[1][n-1] != uint64(2*n) {
		t.Errorf("unexpected sums %v", s)
	}
}
