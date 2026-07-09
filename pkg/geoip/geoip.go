package geoip

import (
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"
	"github.com/sirupsen/logrus"
)

type Provider struct {
	asnDB     *geoip2.Reader
	countryDB *geoip2.Reader
}

// New opens the ASN database, and optionally a GeoLite2-Country/City database
// for country-level enrichment. countryPath may be empty, in which case
// country lookups gracefully return "unknown".
func New(asnPath string, countryPath string) (*Provider, error) {
	if asnPath == "" && countryPath == "" {
		return nil, nil // Graceful degradation if no DB provided
	}

	p := &Provider{}

	if asnPath != "" {
		db, err := geoip2.Open(asnPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open ASN database: %w", err)
		}
		p.asnDB = db
		logrus.WithField("path", asnPath).Info("GeoIP ASN Database Loaded")
	}

	if countryPath != "" {
		db, err := geoip2.Open(countryPath)
		if err != nil {
			p.Close()
			return nil, fmt.Errorf("failed to open Country database: %w", err)
		}
		p.countryDB = db
		logrus.WithField("path", countryPath).Info("GeoIP Country Database Loaded")
	}

	return p, nil
}

func (p *Provider) Close() {
	if p == nil {
		return
	}
	if p.asnDB != nil {
		p.asnDB.Close()
	}
	if p.countryDB != nil {
		p.countryDB.Close()
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

// LookupCountry returns the ISO 3166-1 alpha-2 country code and English name
// for the given IP using the Country/City database. Returns "unknown" for
// both values if no country database was configured or the lookup fails.
func (p *Provider) LookupCountry(ip net.IP) (isoCode string, name string) {
	if p == nil || p.countryDB == nil {
		return "unknown", "unknown"
	}

	record, err := p.countryDB.Country(ip)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"ip":    ip.String(),
			"error": err,
		}).Debug("GeoIP Country Lookup Failed")
		return "unknown", "unknown"
	}

	isoCode = record.Country.IsoCode
	name = record.Country.Names["en"]

	if isoCode == "" {
		isoCode = "unknown"
	}
	if name == "" {
		name = "unknown"
	}

	return isoCode, name
}
