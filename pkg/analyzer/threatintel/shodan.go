package threatintel

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"PacketYeeter/pkg/metrics"
	"PacketYeeter/pkg/utils/limitread"

	"github.com/sirupsen/logrus"
)

const maxShodanCacheEntries = 50000

// ShodanInternetDB provides IP intelligence from Shodan's free InternetDB API
// No API key required, completely free
type ShodanInternetDB struct {
	mu       sync.RWMutex
	cache    map[string]*ShodanIPInfo
	cacheTTL time.Duration
	client   *http.Client

	// Rate limiting
	lastRequest time.Time
	minInterval time.Duration
}

// ShodanIPInfo represents data from Shodan InternetDB
type ShodanIPInfo struct {
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	CPEs      []string `json:"cpes"`      // Common Platform Enumeration
	Hostnames []string `json:"hostnames"` // PTR records
	Tags      []string `json:"tags"`      // Scanner, cloud, tor, vpn, etc.
	Vulns     []string `json:"vulns"`     // CVE IDs
	CachedAt  time.Time

	// Derived fields
	IsScanner bool // Derived from tags
	IsCloud   bool
	IsTor     bool
	IsVPN     bool
	OpenPorts int // Count of open ports
	HasVulns  bool
}

// NewShodanInternetDB creates a new Shodan InternetDB client
func NewShodanInternetDB(cacheTTL time.Duration) *ShodanInternetDB {
	if cacheTTL == 0 {
		cacheTTL = 24 * time.Hour // Cache for 24 hours by default
	}

	s := &ShodanInternetDB{
		cache:       make(map[string]*ShodanIPInfo),
		cacheTTL:    cacheTTL,
		client:      &http.Client{Timeout: 5 * time.Second},
		minInterval: 100 * time.Millisecond, // 10 requests/sec max
	}

	// Start cache cleanup
	go s.cleanupLoop()

	return s
}

// Lookup queries Shodan InternetDB for IP information
func (s *ShodanInternetDB) Lookup(ip net.IP) (*ShodanIPInfo, error) {
	if ip == nil {
		return nil, fmt.Errorf("nil IP")
	}

	ipStr := ip.String()

	// Check cache
	s.mu.RLock()
	cached, ok := s.cache[ipStr]
	s.mu.RUnlock()
	if ok && time.Since(cached.CachedAt) < s.cacheTTL {
		return cached, nil
	}

	// Rate limiting
	s.mu.Lock()
	since := time.Since(s.lastRequest)
	if since < s.minInterval {
		s.mu.Unlock()
		// Return cached if available, even if expired
		if cached != nil {
			return cached, nil
		}
		return nil, fmt.Errorf("rate limited")
	}
	s.lastRequest = time.Now()
	s.mu.Unlock()

	// Fetch from API
	url := fmt.Sprintf("https://internetdb.shodan.io/%s", ipStr)
	metrics.ThreatIntelShodanLookups.Inc()
	resp, err := s.client.Get(url)
	if err != nil {
		metrics.ThreatIntelShodanErrors.Inc()
		// Return stale cache on error
		if cached != nil {
			logrus.WithError(err).Debug("Shodan API error, using stale cache")
			return cached, nil
		}
		return nil, err
	}
	defer resp.Body.Close()

	// 404 means IP not seen by Shodan (clean IP)
	if resp.StatusCode == 404 {
		info := &ShodanIPInfo{
			IP:       ipStr,
			CachedAt: time.Now(),
		}
		s.mu.Lock()
		if _, exists := s.cache[ipStr]; exists || len(s.cache) < maxShodanCacheEntries {
			s.cache[ipStr] = info
		}
		s.mu.Unlock()
		return info, nil
	}

	if resp.StatusCode != http.StatusOK {
		metrics.ThreatIntelShodanErrors.Inc()
		if cached != nil {
			return cached, nil
		}
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// InternetDB answers are small JSON objects; bound the read so a
	// misbehaving upstream cannot drive unbounded allocation.
	body, err := limitread.ReadAll(resp.Body, 1<<20)
	if err != nil {
		if cached != nil {
			return cached, nil
		}
		return nil, err
	}

	var info ShodanIPInfo
	if err := json.Unmarshal(body, &info); err != nil {
		if cached != nil {
			return cached, nil
		}
		return nil, err
	}

	// Process and enrich data
	info.CachedAt = time.Now()
	info.OpenPorts = len(info.Ports)
	info.HasVulns = len(info.Vulns) > 0

	// Parse tags
	for _, tag := range info.Tags {
		switch tag {
		case "scanner", "scanning":
			info.IsScanner = true
		case "cloud":
			info.IsCloud = true
		case "tor":
			info.IsTor = true
		case "vpn", "proxy":
			info.IsVPN = true
		}
	}

	// Cache result
	s.mu.Lock()
	if _, exists := s.cache[ipStr]; exists || len(s.cache) < maxShodanCacheEntries {
		s.cache[ipStr] = &info
	}
	s.mu.Unlock()

	logrus.WithFields(logrus.Fields{
		"ip":         ipStr,
		"ports":      info.OpenPorts,
		"is_scanner": info.IsScanner,
		"is_cloud":   info.IsCloud,
		"vulns":      len(info.Vulns),
	}).Debug("Shodan InternetDB lookup")

	return &info, nil
}

// LookupAsync performs a non-blocking lookup
func (s *ShodanInternetDB) LookupAsync(ip net.IP, callback func(*ShodanIPInfo)) {
	go func() {
		info, err := s.Lookup(ip)
		if err != nil {
			logrus.WithError(err).WithField("ip", ip.String()).Debug("Shodan lookup failed")
			return
		}
		if callback != nil {
			callback(info)
		}
	}()
}

// GetCached returns cached info if available
func (s *ShodanInternetDB) GetCached(ip net.IP) *ShodanIPInfo {
	if ip == nil {
		return nil
	}

	s.mu.RLock()
	info, ok := s.cache[ip.String()]
	s.mu.RUnlock()

	if !ok {
		return nil
	}

	// Return even if expired - caller can check CachedAt
	return info
}

// cleanupLoop periodically removes expired cache entries
func (s *ShodanInternetDB) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		s.cleanup()
	}
}

// cleanup removes expired cache entries
func (s *ShodanInternetDB) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	expiry := s.cacheTTL * 2 // Keep stale entries for 2x TTL

	for ip, info := range s.cache {
		if now.Sub(info.CachedAt) > expiry {
			delete(s.cache, ip)
		}
	}
}

// GetStats returns cache statistics
func (s *ShodanInternetDB) GetStats() (cacheSize int, scanners int, cloud int, tor int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cacheSize = len(s.cache)
	for _, info := range s.cache {
		if info.IsScanner {
			scanners++
		}
		if info.IsCloud {
			cloud++
		}
		if info.IsTor {
			tor++
		}
	}

	return
}
