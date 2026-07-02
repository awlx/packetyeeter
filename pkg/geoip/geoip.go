package geoip

import (
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"
	"github.com/sirupsen/logrus"
)

type Provider struct {
	asnDB *geoip2.Reader
}

func New(asnPath string) (*Provider, error) {
	if asnPath == "" {
		return nil, nil // Graceful degradation if no DB provided
	}

	db, err := geoip2.Open(asnPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open ASN database: %w", err)
	}

	logrus.WithField("path", asnPath).Info("GeoIP ASN Database Loaded")
	return &Provider{asnDB: db}, nil
}

func (p *Provider) Close() {
	if p != nil && p.asnDB != nil {
		p.asnDB.Close()
	}
}

func (p *Provider) Lookup(ip net.IP) (asn string, org string) {
	if p == nil || p.asnDB == nil {
		return "unknown", "unknown"
	}

	record, err := p.asnDB.ASN(ip)
	if err != nil {
		// Log detailed error for debugging purposes (limited to Debug to avoid spam)
		logrus.WithFields(logrus.Fields{
			"ip":    ip.String(),
			"error": err,
		}).Debug("GeoIP Lookup Failed")
		return "unknown", "unknown"
	}

	asn = fmt.Sprintf("AS%d", record.AutonomousSystemNumber)
	org = record.AutonomousSystemOrganization

	if asn == "AS0" {
		asn = "unknown"
	}
	if org == "" {
		org = "unknown"
	}

	return asn, org
}

// LookupWithDefaults performs a GeoIP lookup and returns "Unknown" for empty values
// This is a convenience wrapper to avoid repeating the "Unknown" default pattern
func (p *Provider) LookupWithDefaults(ip net.IP) (asn string, org string) {
	asn, org = p.Lookup(ip)

	if asn == "" || asn == "unknown" {
		asn = "Unknown"
	}
	if org == "" || org == "unknown" {
		org = "Unknown"
	}

	return asn, org
}
