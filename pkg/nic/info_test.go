package nic

import (
	"reflect"
	"strings"
	"testing"
)

const ringsOut = `Ring parameters for eth0:
Pre-set maximums:
RX:			8192
RX Mini:		n/a
RX Jumbo:		n/a
TX:			8192
Current hardware settings:
RX:			512
RX Mini:		n/a
RX Jumbo:		n/a
TX:			1024
RX Buf Len:		n/a
`

const channelsOut = `Channel parameters for eth0:
Pre-set maximums:
RX:		n/a
TX:		n/a
Other:		1
Combined:	63
Current hardware settings:
RX:		n/a
TX:		n/a
Other:		1
Combined:	8
`

const featuresOut = `Features for eth0:
rx-checksumming: on
receive-hashing: on
large-receive-offload: off [fixed]
rx-gro-hw: on
ntuple-filters: off
hw-tc-offload: off [fixed]
`

func TestParseEthtool(t *testing.T) {
	if got := parseEthtoolRings(ringsOut); *got != (MaxCur{Max: 8192, Cur: 512}) {
		t.Errorf("rings = %+v", *got)
	}
	if got := parseEthtoolChannels(channelsOut); *got != (MaxCur{Max: 63, Cur: 8}) {
		t.Errorf("channels = %+v", *got)
	}
	if got := parseEthtoolRings("nothing here"); got != nil {
		t.Errorf("rings from garbage = %+v", *got)
	}
	f := parseEthtoolFeatures(featuresOut)
	want := map[string]Offload{
		"rx-checksumming":       {On: true},
		"receive-hashing":       {On: true},
		"large-receive-offload": {Fixed: true},
		"rx-gro-hw":             {On: true},
		"ntuple-filters":        {},
		"hw-tc-offload":         {Fixed: true},
	}
	if !reflect.DeepEqual(f, want) {
		t.Errorf("features = %+v", f)
	}
}

func TestParseCPUList(t *testing.T) {
	if got := parseCPUList("0-3,8,10-11"); !reflect.DeepEqual(got, []int{0, 1, 2, 3, 8, 10, 11}) {
		t.Errorf("got %v", got)
	}
	if got := parseCPUList(""); got != nil {
		t.Errorf("empty list = %v", got)
	}
}

func TestFeatureStrings(t *testing.T) {
	if s := (XDPBasic | XDPRedirect | XDPNdoXmit).String(); s != "basic,redirect,ndo-xmit" {
		t.Errorf("got %q", s)
	}
	if s := XDPFeatures(0).String(); s != "none" {
		t.Errorf("got %q", s)
	}
	if s := (RxMetaHash | RxMetaVLANTag).String(); s != "hash,vlan-tag" {
		t.Errorf("got %q", s)
	}
}

func TestScrubPortWarnings(t *testing.T) {
	full := &DevFeatures{XDP: XDPBasic | XDPRedirect | XDPNdoXmit}
	if w := ScrubPortWarnings("outside", false, full); len(w) != 0 {
		t.Errorf("native, full features: %v", w)
	}
	if w := ScrubPortWarnings("inside", false, &DevFeatures{XDP: XDPBasic | XDPRedirect}); len(w) != 1 ||
		!strings.Contains(w[0], "ndo_xdp_xmit") {
		t.Errorf("inside without ndo-xmit: %v", w)
	}
	if w := ScrubPortWarnings("outside", false, &DevFeatures{XDP: XDPBasic}); len(w) != 1 ||
		!strings.Contains(w[0], "XDP_REDIRECT") {
		t.Errorf("outside without redirect: %v", w)
	}
	if w := ScrubPortWarnings("inside", true, nil); len(w) != 1 || !strings.Contains(w[0], "generic") {
		t.Errorf("generic: %v", w)
	}
	if w := ScrubPortWarnings("inside", false, nil); len(w) != 0 {
		t.Errorf("unknown features must not warn: %v", w)
	}
}

func TestCheckFindings(t *testing.T) {
	info := &Info{
		Name: "eth0", Driver: "mlx5_core", MTU: 1500, CPUs: 32, NUMANode: 0,
		NUMACPUs: []int{0, 1, 2, 3, 4, 5, 6, 7}, RxQueues: 1, IRQCPUs: []int{0, 9},
		XDPMode:  AttachGeneric,
		Features: &DevFeatures{XDP: XDPBasic | XDPRedirect | XDPNdoXmit},
		Offloads: map[string]Offload{"rx-gro-hw": {On: true}},
		Rings:    &MaxCur{Max: 8192, Cur: 512},
	}
	var warns []string
	for _, f := range Check(info, "outside") {
		if f.Level == LevelWarn {
			warns = append(warns, f.Text)
		}
	}
	all := strings.Join(warns, "\n")
	for _, want := range []string{"generic (skb) mode", "rx-gro-hw is on", "single RX queue", "outside NUMA node 0"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing warning %q in:\n%s", want, all)
		}
	}
}

func TestModel(t *testing.T) {
	if r := LineRateMpps(10000, 64); r < 14.87 || r > 14.89 {
		t.Errorf("10G 64B = %.3f Mpps, want 14.88", r)
	}
	if r := LineRateMpps(100000, 64); r < 148.8 || r > 148.9 {
		t.Errorf("100G 64B = %.3f Mpps, want 148.81", r)
	}
	if CoresFor(14.88, 5) != 3 || CoresFor(10, 0) != 0 {
		t.Error("CoresFor")
	}
	for _, p := range Profiles {
		for _, pr := range Predict(p) {
			lo, hi := pr.PerCoreMpps[0], pr.PerCoreMpps[1]
			if !(lo > 0 && lo <= hi) {
				t.Errorf("%s/%s: bad range %v", p.Name, pr.Scenario.Name, pr.PerCoreMpps)
			}
		}
	}
	p, ok := LookupDriver("mlx5_core")
	if !ok {
		t.Fatal("mlx5_core not modelled")
	}
	preds := Predict(p)
	if preds[0].PerCoreMpps[1] <= preds[1].PerCoreMpps[1] {
		t.Error("rules must cost throughput")
	}
	var b strings.Builder
	WritePrediction(&b, "mlx5_core", 100000)
	if !strings.Contains(b.String(), "148.81 Mpps at 64B") {
		t.Errorf("report:\n%s", b.String())
	}
}
