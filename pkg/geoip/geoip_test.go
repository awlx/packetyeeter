package geoip

import (
	"net"
	"testing"
)

func TestNewNoPaths(t *testing.T) {
	p, err := New("", "")
	if err != nil {
		t.Fatalf("expected no error for empty paths, got %v", err)
	}
	if p != nil {
		t.Fatalf("expected nil provider for empty paths, got %v", p)
	}
}

func TestLookupNilProvider(t *testing.T) {
	var p *Provider
	asn, org := p.Lookup(net.ParseIP("1.2.3.4"))
	if asn != "unknown" || org != "unknown" {
		t.Fatalf("expected unknown/unknown for nil provider, got %s/%s", asn, org)
	}
}

func TestLookupCountryNilProvider(t *testing.T) {
	var p *Provider
	code, name := p.LookupCountry(net.ParseIP("1.2.3.4"))
	if code != "unknown" || name != "unknown" {
		t.Fatalf("expected unknown/unknown for nil provider, got %s/%s", code, name)
	}
}

func TestLookupCountryNoCountryDB(t *testing.T) {
	// Provider with no country DB configured (e.g. only ASN DB loaded, or
	// neither DB present) must gracefully degrade rather than panic.
	p := &Provider{}
	code, name := p.LookupCountry(net.ParseIP("8.8.8.8"))
	if code != "unknown" || name != "unknown" {
		t.Fatalf("expected unknown/unknown when no country DB configured, got %s/%s", code, name)
	}
}

func TestNewInvalidPaths(t *testing.T) {
	if _, err := New("/nonexistent/GeoLite2-ASN.mmdb", ""); err == nil {
		t.Fatal("expected error for nonexistent ASN db path")
	}
	if _, err := New("", "/nonexistent/GeoLite2-Country.mmdb"); err == nil {
		t.Fatal("expected error for nonexistent Country db path")
	}
}

func TestCloseNilProvider(t *testing.T) {
	var p *Provider
	p.Close() // must not panic
}
