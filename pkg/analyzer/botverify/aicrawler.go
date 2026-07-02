package botverify

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// AICrawlerType represents the type of AI crawler
type AICrawlerType string

const (
	AICrawlerOpenAIGPT     AICrawlerType = "openai-gptbot"
	AICrawlerOpenAISearch  AICrawlerType = "openai-searchbot"
	AICrawlerOpenAIChatGPT AICrawlerType = "openai-chatgpt"
	AICrawlerAmazonBot     AICrawlerType = "amazonbot"
)

// AICrawlerSource defines a source URL for fetching crawler IPs
type AICrawlerSource struct {
	Type       AICrawlerType
	URL        string
	ParseFunc  func([]byte) ([]string, error)
	UserAgents []string // User-Agent patterns to match
}

// AICrawlerRegistry maintains a list of verified AI crawler IPs
type AICrawlerRegistry struct {
	mu       sync.RWMutex
	ipNets   map[AICrawlerType][]*net.IPNet // CIDR ranges for each crawler
	sources  []AICrawlerSource
	updateAt time.Time
	ttl      time.Duration
}

// OpenAI JSON format - contains objects with ipv4Prefix/ipv6Prefix
type openAIIPList struct {
	Prefixes []struct {
		IPv4Prefix string `json:"ipv4Prefix"`
		IPv6Prefix string `json:"ipv6Prefix"`
	} `json:"prefixes"`
}

// Amazon text format - just list of IPs/CIDRs
func parseAmazonIPList(data []byte) ([]string, error) {
	// Amazon's page is HTML with JSON embedded, and quotes are HTML-encoded
	// First, decode HTML entities (&quot; -> ")
	htmlDecoded := decodeHTMLEntities(string(data))

	// Try to extract JSON from HTML
	// Look for pattern: "ipv4Prefix": "IP"
	var result []string
	lines := splitLines(htmlDecoded)
	for _, line := range lines {
		// Extract IP from: "ipv4Prefix": "1.2.3.4"
		if contains(line, "ipv4Prefix") {
			// Find the IP between quotes after ipv4Prefix
			start := indexOf(line, "ipv4Prefix")
			if start >= 0 {
				// Find the value after the colon
				colonIdx := indexOf(line[start:], ":")
				if colonIdx >= 0 {
					afterColon := line[start+colonIdx+1:]
					// Find first quote
					firstQuote := indexOf(afterColon, "\"")
					if firstQuote >= 0 {
						afterQuote := afterColon[firstQuote+1:]
						// Find closing quote
						secondQuote := indexOf(afterQuote, "\"")
						if secondQuote > 0 {
							ip := afterQuote[:secondQuote]
							ip = trimSpace(ip)
							if ip != "" {
								result = append(result, ip)
							}
						}
					}
				}
			}
		}
	}

	if len(result) == 0 {
		// Fallback: try parsing as plain text list
		result = parseTextList(data)
	}

	return result, nil
}

func decodeHTMLEntities(s string) string {
	// Simple decoder for common entities
	s = replaceAll(s, "&quot;", "\"")
	s = replaceAll(s, "&amp;", "&")
	s = replaceAll(s, "&lt;", "<")
	s = replaceAll(s, "&gt;", ">")
	return s
}

func replaceAll(s, old, new string) string {
	result := ""
	for {
		idx := indexOf(s, old)
		if idx < 0 {
			result += s
			break
		}
		result += s[:idx] + new
		s = s[idx+len(old):]
	}
	return result
}

// OpenAI JSON format parser
func parseOpenAIIPList(data []byte) ([]string, error) {
	var list openAIIPList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}

	var result []string
	for _, prefix := range list.Prefixes {
		if prefix.IPv4Prefix != "" {
			result = append(result, prefix.IPv4Prefix)
		}
		if prefix.IPv6Prefix != "" {
			result = append(result, prefix.IPv6Prefix)
		}
	}
	return result, nil
}

// Parse plain text list (one IP/CIDR per line)
func parseTextList(data []byte) []string {
	var result []string
	lines := string(data)
	for _, line := range splitLines(lines) {
		line = trimSpace(line)
		if line != "" && !startsWith(line, "#") {
			result = append(result, line)
		}
	}
	return result
}

// Helper functions to avoid importing strings package
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\r' || s[end-1] == '\n') {
		end--
	}
	return s[start:end]
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// Known AI crawler sources
var DefaultAICrawlerSources = []AICrawlerSource{
	{
		Type:       AICrawlerOpenAIGPT,
		URL:        "https://openai.com/gptbot.json",
		ParseFunc:  parseOpenAIIPList,
		UserAgents: []string{"GPTBot"},
	},
	{
		Type:       AICrawlerOpenAISearch,
		URL:        "https://openai.com/searchbot.json",
		ParseFunc:  parseOpenAIIPList,
		UserAgents: []string{"OAI-SearchBot"},
	},
	{
		Type:       AICrawlerOpenAIChatGPT,
		URL:        "https://openai.com/chatgpt-user.json",
		ParseFunc:  parseOpenAIIPList,
		UserAgents: []string{"ChatGPT-User"},
	},
	{
		Type:       AICrawlerAmazonBot,
		URL:        "https://developer.amazon.com/amazonbot/ip-addresses/",
		ParseFunc:  parseAmazonIPList,
		UserAgents: []string{"Amazonbot"},
	},
}

// NewAICrawlerRegistry creates a new AI crawler registry
func NewAICrawlerRegistry(ttl time.Duration) *AICrawlerRegistry {
	if ttl == 0 {
		ttl = 24 * time.Hour // Update daily by default
	}

	r := &AICrawlerRegistry{
		ipNets:  make(map[AICrawlerType][]*net.IPNet),
		sources: DefaultAICrawlerSources,
		ttl:     ttl,
	}

	// Initial fetch
	go r.Update()

	// Start periodic update
	go r.updateLoop()

	return r
}

// Update fetches the latest IP lists from all sources
func (r *AICrawlerRegistry) Update() {
	logrus.Info("Updating AI crawler IP lists")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	newIPNets := make(map[AICrawlerType][]*net.IPNet)

	for _, source := range r.sources {
		ips, err := r.fetchSource(client, source)
		if err != nil {
			logrus.WithError(err).WithField("source", source.URL).Warn("Failed to fetch AI crawler IPs")
			continue
		}

		// Parse IPs/CIDRs into IPNet objects
		var ipNets []*net.IPNet
		for _, ipStr := range ips {
			// Try parsing as CIDR
			_, ipNet, err := net.ParseCIDR(ipStr)
			if err != nil {
				// Try parsing as single IP
				ip := net.ParseIP(ipStr)
				if ip != nil {
					// Convert single IP to /32 or /128 CIDR
					if ip.To4() != nil {
						_, ipNet, _ = net.ParseCIDR(ipStr + "/32")
					} else {
						_, ipNet, _ = net.ParseCIDR(ipStr + "/128")
					}
				}
			}
			if ipNet != nil {
				ipNets = append(ipNets, ipNet)
			}
		}

		newIPNets[source.Type] = ipNets

		logrus.WithFields(logrus.Fields{
			"type":  source.Type,
			"count": len(ipNets),
		}).Info("Updated AI crawler IP list")
	}

	// Update registry
	r.mu.Lock()
	r.ipNets = newIPNets
	r.updateAt = time.Now()
	r.mu.Unlock()
}

// fetchSource fetches and parses a single source
func (r *AICrawlerRegistry) fetchSource(client *http.Client, source AICrawlerSource) ([]string, error) {
	resp, err := client.Get(source.URL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logrus.WithField("status", resp.StatusCode).Errorf("HTTP error fetching %s", source.URL)
		return nil, fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, source.URL)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return source.ParseFunc(data)
}

// IsAICrawler checks if an IP belongs to a known AI crawler
func (r *AICrawlerRegistry) IsAICrawler(ip net.IP) (bool, AICrawlerType) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for crawlerType, ipNets := range r.ipNets {
		for _, ipNet := range ipNets {
			if ipNet.Contains(ip) {
				return true, crawlerType
			}
		}
	}

	return false, ""
}

// MatchUserAgent checks if a user agent matches any known AI crawler
func (r *AICrawlerRegistry) MatchUserAgent(userAgent string) (AICrawlerType, bool) {
	for _, source := range r.sources {
		for _, pattern := range source.UserAgents {
			if contains(userAgent, pattern) {
				return source.Type, true
			}
		}
	}
	return "", false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && indexOf(s, substr) >= 0
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// VerifyAICrawler checks if IP and User-Agent match a known AI crawler
func (r *AICrawlerRegistry) VerifyAICrawler(ip net.IP, userAgent string) (bool, AICrawlerType) {
	// Check user agent first
	crawlerType, hasUA := r.MatchUserAgent(userAgent)
	if !hasUA {
		return false, ""
	}

	// Verify IP matches the claimed crawler
	isValid, ipType := r.IsAICrawler(ip)
	if !isValid {
		return false, ""
	}

	// IP and UA must match
	if crawlerType != ipType {
		return false, ""
	}

	return true, crawlerType
}

// updateLoop periodically refreshes the IP lists
func (r *AICrawlerRegistry) updateLoop() {
	ticker := time.NewTicker(r.ttl)
	defer ticker.Stop()

	for range ticker.C {
		r.Update()
	}
}

// GetStats returns statistics about the registry
func (r *AICrawlerRegistry) GetStats() map[AICrawlerType]int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := make(map[AICrawlerType]int)
	for crawlerType, ipNets := range r.ipNets {
		stats[crawlerType] = len(ipNets)
	}
	return stats
}
