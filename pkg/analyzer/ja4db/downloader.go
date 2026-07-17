package ja4db

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"PacketYeeter/pkg/metrics"

	"github.com/sirupsen/logrus"
)

// Bot detection keywords (shared with analyzer package to avoid circular imports)
var (
	BotKeywordsBasic    = []string{"bot", "crawler", "spider", "scraper", "scanner"}
	BotKeywordsExtended = []string{"bot", "crawler", "spider", "scraper", "curl", "wget", "python", "java", "go-http"}
)

const (
	// JA4DBURL was the free, keyless JA4DB bulk-download API. As of 2026,
	// ja4db.com redirects here and FoxIO's ja4db.foxio.io no longer serves
	// this endpoint publicly (it now requires an authenticated account) -
	// the request reliably returns 404. Kept as the primary source in case
	// it is restored; FallbackURL below is used when it fails.
	JA4DBURL = "https://ja4db.com/api/download/"

	// FallbackURL is FoxIO's public, unauthenticated, community-maintained
	// JA4+ mapping CSV from the ja4 GitHub repo. It is much smaller than the
	// old JA4DB bulk export and lacks fields like ObservationCount/Verified/
	// CertificateAuthority, but it is free, keyless, and currently live.
	FallbackURL = "https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4plus-mapping.csv"

	UpdateInterval   = 12 * time.Hour
	DefaultCachePath = "/var/cache/packetyeeter/ja4db.json"
)

// JA4Entry represents a single entry in the JA4 database
type JA4Entry struct {
	Application          string `json:"application"`
	Library              string `json:"library"`
	Device               string `json:"device"`
	OS                   string `json:"os"`
	UserAgentString      string `json:"user_agent_string"`
	CertificateAuthority string `json:"certificate_authority"`
	ObservationCount     int    `json:"observation_count"`
	Verified             bool   `json:"verified"`
	Notes                string `json:"notes"`
	JA4Fingerprint       string `json:"ja4_fingerprint"`
	JA4FingerprintString string `json:"ja4_fingerprint_string"`
	JA4SFingerprint      string `json:"ja4s_fingerprint"`
	JA4HFingerprint      string `json:"ja4h_fingerprint"`
	JA4XFingerprint      string `json:"ja4x_fingerprint"`
	JA4TFingerprint      string `json:"ja4t_fingerprint"`
	JA4TSFingerprint     string `json:"ja4ts_fingerprint"`
	JA4TScanFingerprint  string `json:"ja4tscan_fingerprint"`
}

// GetSearchableText returns all relevant text fields concatenated and lowercased for searching
func (e JA4Entry) GetSearchableText() string {
	return strings.ToLower(e.Application + " " + e.Library + " " + e.Device + " " + e.UserAgentString + " " + e.Notes)
}

// JA4Database holds the loaded JA4 database with separate maps for different fingerprint types
type JA4Database struct {
	LastUpdated time.Time
	Version     string
	// Source records where the currently loaded data came from: "primary"
	// (JA4DBURL), "fallback" (FallbackURL), or "cache" (on-disk cache from
	// a previous run). Useful for distinguishing full-fidelity data from
	// the reduced-fidelity community CSV fallback.
	Source              string
	Entries             map[string]JA4Entry // ja4_fingerprint -> entry
	EntriesByJA4Prefix  map[string]JA4Entry // ja4 wildcard key: 'a_b' segments (see ja4WildcardPrefix) -> entry
	EntriesByJA4H       map[string]JA4Entry // ja4h_fingerprint -> entry
	EntriesByJA4HPrefix map[string]JA4Entry // ja4h headers prefix -> entry (first match)
	EntriesByJA4T       map[string]JA4Entry // ja4t_fingerprint -> entry
	mu                  sync.RWMutex
}

// Downloader manages periodic downloads of the JA4 database
type Downloader struct {
	CachePath string
	Client    *http.Client
	DB        *JA4Database
	logger    *logrus.Logger
	ctx       context.Context
	cancel    context.CancelFunc

	// primaryURL and fallbackURL default to JA4DBURL and FallbackURL but are
	// overridable (unexported, test-only) so unit tests can point at local
	// httptest servers instead of real network endpoints.
	primaryURL  string
	fallbackURL string
}

// NewDownloader creates a new JA4 database downloader
func NewDownloader(cachePath string, logger *logrus.Logger) *Downloader {
	if cachePath == "" {
		cachePath = DefaultCachePath
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Downloader{
		CachePath: cachePath,
		Client: &http.Client{
			Timeout: 120 * time.Second,
		},
		DB: &JA4Database{
			Entries:             make(map[string]JA4Entry),
			EntriesByJA4Prefix:  make(map[string]JA4Entry),
			EntriesByJA4H:       make(map[string]JA4Entry),
			EntriesByJA4HPrefix: make(map[string]JA4Entry),
			EntriesByJA4T:       make(map[string]JA4Entry),
		},
		logger:      logger,
		ctx:         ctx,
		cancel:      cancel,
		primaryURL:  JA4DBURL,
		fallbackURL: FallbackURL,
	}
}

// Start begins the periodic download process
func (d *Downloader) Start() error {
	// Ensure cache directory exists
	cacheDir := filepath.Dir(d.CachePath)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Load from cache if exists
	if err := d.loadFromCache(); err != nil {
		d.logger.WithError(err).Warn("Failed to load JA4 database from cache, will download fresh")
	} else {
		d.logger.WithFields(logrus.Fields{
			"ja4_entries":  len(d.DB.Entries),
			"ja4h_entries": len(d.DB.EntriesByJA4H),
			"last_updated": d.DB.LastUpdated,
			"age_hours":    time.Since(d.DB.LastUpdated).Hours(),
		}).Info("JA4 database loaded from cache on startup")
	}

	// Start periodic updater
	go d.periodicUpdate()

	// Initial download if cache is old, empty, or doesn't exist (async)
	needsDownload := false
	if len(d.DB.Entries) == 0 {
		d.logger.Info("JA4 database is empty, will download")
		needsDownload = true
	} else if time.Since(d.DB.LastUpdated) > UpdateInterval {
		d.logger.WithFields(logrus.Fields{
			"age_hours": time.Since(d.DB.LastUpdated).Hours(),
		}).Info("JA4 database is outdated, will download")
		needsDownload = true
	} else {
		d.logger.Info("JA4 database is recent, skipping initial download")
	}

	if needsDownload {
		go func() {
			if err := d.Download(); err != nil {
				d.logger.WithError(err).Error("Initial JA4 database download failed")
			}
		}()
	}

	d.logger.WithFields(logrus.Fields{
		"cache_path":   d.CachePath,
		"interval":     UpdateInterval,
		"ja4_entries":  len(d.DB.Entries),
		"ja4h_entries": len(d.DB.EntriesByJA4H),
	}).Info("JA4 database downloader started")

	return nil
}

// Stop stops the periodic downloader
func (d *Downloader) Stop() {
	d.cancel()
}

// periodicUpdate runs the download process every 12 hours
func (d *Downloader) periodicUpdate() {
	ticker := time.NewTicker(UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			d.logger.Info("JA4 database downloader stopped")
			return
		case <-ticker.C:
			if err := d.Download(); err != nil {
				d.logger.WithError(err).Error("Failed to update JA4 database")
			}
		}
	}
}

// Download fetches the latest JA4 database. It tries the primary JA4DBURL
// first; if that fails (e.g. the free bulk-download API is unavailable or
// has been removed upstream), it falls back to FallbackURL, FoxIO's public
// JA4+ mapping CSV, which is smaller and lower-fidelity but free and keyless.
func (d *Downloader) Download() error {
	d.logger.Info("Downloading JA4 database...")

	entries, version, err := d.fetchPrimary()
	source := "primary"
	if err != nil {
		if isNotFoundErr(err) {
			d.logger.WithError(err).Warn(
				"Primary JA4DB endpoint returned 404 - the free bulk-download API " +
					"appears to have been removed or moved behind authentication " +
					"upstream, not a transient outage. Falling back to the community " +
					"JA4+ mapping CSV (smaller, reduced-fidelity data).")
		} else {
			d.logger.WithError(err).Warn("Primary JA4DB download failed, trying fallback source")
		}

		entries, err = d.fetchFallback()
		source = "fallback"
		if err != nil {
			return fmt.Errorf("primary and fallback JA4 database downloads both failed: %w", err)
		}
	}

	if len(entries) == 0 {
		return fmt.Errorf("received empty database from %s source", source)
	}

	d.applyEntries(entries, source, version)

	// Save to cache (just the array format) so a future restart can load it
	// even if both sources are unreachable at that time.
	if err := d.saveToCache(entries); err != nil {
		d.logger.WithError(err).Warn("Failed to save JA4 database to cache")
	}

	return nil
}

// fetchPrimary downloads and parses the JSON array from JA4DBURL.
func (d *Downloader) fetchPrimary() ([]JA4Entry, string, error) {
	req, err := http.NewRequestWithContext(d.ctx, "GET", d.primaryURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to download database: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", &notFoundError{statusCode: resp.StatusCode}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read response: %w", err)
	}

	d.logger.WithField("body_size", len(body)).Debug("Downloaded JA4 database (primary)")

	var entries []JA4Entry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, "", fmt.Errorf("failed to parse database: %w", err)
	}

	return entries, resp.Header.Get("X-JA4DB-Version"), nil
}

// fetchFallback downloads and parses the community JA4+ mapping CSV from
// FallbackURL when the primary source is unavailable.
func (d *Downloader) fetchFallback() ([]JA4Entry, error) {
	req, err := http.NewRequestWithContext(d.ctx, "GET", d.fallbackURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create fallback request: %w", err)
	}

	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download fallback database: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected fallback status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read fallback response: %w", err)
	}

	d.logger.WithField("body_size", len(body)).Debug("Downloaded JA4 database (fallback CSV)")

	entries, err := parseJA4PlusCSV(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse fallback CSV: %w", err)
	}

	return entries, nil
}

// notFoundError distinguishes an HTTP-level "not found" response (the
// endpoint itself is gone) from other transport/parse failures, so callers
// can log a more accurate message instead of a generic timeout/network error.
type notFoundError struct {
	statusCode int
}

func (e *notFoundError) Error() string {
	return fmt.Sprintf("unexpected status code: %d", e.statusCode)
}

func isNotFoundErr(err error) bool {
	nfe, ok := err.(*notFoundError)
	return ok && nfe.statusCode == http.StatusNotFound
}

// parseJA4PlusCSV parses FoxIO's ja4plus-mapping.csv format:
// Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes
// Column order/presence is read from the header row rather than assumed, so
// upstream column reordering or additions don't silently corrupt the data.
func parseJA4PlusCSV(data []byte) ([]JA4Entry, error) {
	r := csv.NewReader(strings.NewReader(string(data)))
	r.FieldsPerRecord = -1 // tolerate short/blank trailing fields

	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV header: %w", err)
	}

	col := make(map[string]int, len(header))
	for i, name := range header {
		col[strings.ToLower(strings.TrimSpace(name))] = i
	}

	get := func(row []string, name string) string {
		idx, ok := col[name]
		if !ok || idx >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[idx])
	}

	var entries []JA4Entry
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read CSV row: %w", err)
		}

		entry := JA4Entry{
			Application:         get(row, "application"),
			Library:             get(row, "library"),
			Device:              get(row, "device"),
			OS:                  get(row, "os"),
			Notes:               get(row, "notes"),
			JA4Fingerprint:      get(row, "ja4"),
			JA4SFingerprint:     get(row, "ja4s"),
			JA4HFingerprint:     get(row, "ja4h"),
			JA4XFingerprint:     get(row, "ja4x"),
			JA4TFingerprint:     get(row, "ja4t"),
			JA4TScanFingerprint: get(row, "ja4tscan"),
		}

		// Skip fully empty rows (no fingerprint of any kind to index on).
		if entry.JA4Fingerprint == "" && entry.JA4HFingerprint == "" && entry.JA4TFingerprint == "" {
			continue
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// ja4WildcardPrefix returns the JA4 wildcard-matching key for a raw JA4
// fingerprint: the 'a' (TLS version/SNI/cipher+extension counts/ALPN) and 'b'
// (raw cipher list hash) segments joined. Matching on 'a' alone is too coarse
// -- it is shared by thousands of unrelated clients, including common browser
// stacks -- so an exact-miss lookup keyed only on 'a' returned an essentially
// arbitrary same-prefix DB entry as a positive wildcard match. Requiring
// 'a'+'b' narrows collisions enough for the wildcard match to be meaningful.
// Returns ("", false) if the fingerprint has fewer than two underscore-
// separated segments.
func ja4WildcardPrefix(fingerprint string) (string, bool) {
	parts := strings.Split(fingerprint, "_")
	if len(parts) < 2 {
		return "", false
	}
	return parts[0] + "_" + parts[1], true
}

// applyEntries indexes entries into the lookup maps and atomically swaps
// them into the live database, recording which source they came from.
func (d *Downloader) applyEntries(entries []JA4Entry, source, version string) {
	entriesMap := make(map[string]JA4Entry)
	entriesByJA4Prefix := make(map[string]JA4Entry)
	entriesByJA4H := make(map[string]JA4Entry)
	entriesByJA4HPrefix := make(map[string]JA4Entry)
	entriesByJA4T := make(map[string]JA4Entry)

	for _, entry := range entries {
		if entry.JA4Fingerprint != "" {
			entriesMap[entry.JA4Fingerprint] = entry
			if prefix, ok := ja4WildcardPrefix(entry.JA4Fingerprint); ok {
				if _, exists := entriesByJA4Prefix[prefix]; !exists {
					entriesByJA4Prefix[prefix] = entry
				}
			}
		}
		if entry.JA4HFingerprint != "" {
			entriesByJA4H[entry.JA4HFingerprint] = entry
			if parts := strings.Split(entry.JA4HFingerprint, "_"); len(parts) >= 2 {
				prefix := parts[0] + "_" + parts[1]
				if _, exists := entriesByJA4HPrefix[prefix]; !exists {
					entriesByJA4HPrefix[prefix] = entry
				}
			}
		}
		if entry.JA4TFingerprint != "" {
			entriesByJA4T[entry.JA4TFingerprint] = entry
		}
	}

	d.DB.mu.Lock()
	d.DB.Entries = entriesMap
	d.DB.EntriesByJA4Prefix = entriesByJA4Prefix
	d.DB.EntriesByJA4H = entriesByJA4H
	d.DB.EntriesByJA4HPrefix = entriesByJA4HPrefix
	d.DB.EntriesByJA4T = entriesByJA4T
	d.DB.LastUpdated = time.Now()
	d.DB.Version = version
	d.DB.Source = source
	d.DB.mu.Unlock()

	d.logger.WithFields(logrus.Fields{
		"ja4_entries":  len(entriesMap),
		"ja4h_entries": len(entriesByJA4H),
		"ja4t_entries": len(entriesByJA4T),
		"version":      version,
		"source":       source,
	}).Info("JA4 database updated successfully")
}

// LookupResult captures a lookup outcome
// MatchType: exact|wildcard_cd
// FingerprintType: ja4|ja4h|ja4t
// Entry: matched JA4Entry
// Note: JA4 wildcard matching is not implemented; only JA4H headers prefix
// is supported as a limited wildcard (wildcard_cd)
type LookupResult struct {
	Entry           JA4Entry
	MatchType       string
	FingerprintType string
}

// Lookup searches the database for a given JA4, JA4H, or JA4T fingerprint
func (d *Downloader) Lookup(fingerprint string) (interface{}, bool) {
	res, ok := d.LookupWithTypeResult(fingerprint, "")
	return res.Entry, ok
}

func guessFPType(fp string) string {
	if fp == "" {
		return "ja4"
	}
	if strings.Contains(fp, "_") {
		// JA4 (TLS) typically starts with 't' and is shorter; JA4H (HTTP) starts with 'h'
		if strings.HasPrefix(fp, "h") {
			return "ja4h"
		}
		if strings.HasPrefix(fp, "t") {
			return "ja4"
		}
		if len(fp) > 60 {
			return "ja4h"
		}
		return "ja4"
	}
	if len(fp) > 60 {
		return "ja4h"
	}
	return "ja4"
}

// LookupWithType searches the database for a given fingerprint and type hint (ja4, ja4h, ja4t)
func (d *Downloader) LookupWithType(fingerprint string, fpType string) (interface{}, bool) {
	res, ok := d.LookupWithTypeResult(fingerprint, fpType)
	return res.Entry, ok
}

// LookupWithTypeResult searches the database and returns a detailed result
func (d *Downloader) LookupWithTypeResult(fingerprint string, fpType string) (LookupResult, bool) {
	if fpType == "" {
		fpType = guessFPType(fingerprint)
	}

	metrics.JA4DBLookups.Inc()
	metrics.JA4DBLookupsByType.WithLabelValues(fpType).Inc()
	start := time.Now()
	defer func() {
		metrics.JA4DBLookupLatency.Observe(time.Since(start).Seconds())
	}()

	d.DB.mu.RLock()
	defer d.DB.mu.RUnlock()

	matchType := ""
	entry, found := d.DB.Entries[fingerprint]
	if found {
		matchType = "exact"
	} else {
		// Try JA4H
		entry, found = d.DB.EntriesByJA4H[fingerprint]
		if found {
			fpType = "ja4h"
			matchType = "exact"
		} else if fpType == "ja4h" {
			// Try JA4H headers prefix wildcard (first two parts)
			if parts := strings.Split(fingerprint, "_"); len(parts) >= 2 {
				prefix := parts[0] + "_" + parts[1]
				if e, ok := d.DB.EntriesByJA4HPrefix[prefix]; ok {
					entry = e
					found = true
					matchType = "wildcard_cd"
				}
			}
		}
		if !found && fpType == "ja4" {
			// JA4 wildcard: match on 'a'+'b' segments (see ja4WildcardPrefix).
			// The 'a' segment alone is shared by thousands of unrelated
			// clients, so it cannot safely stand in for a positive match.
			if prefix, ok := ja4WildcardPrefix(fingerprint); ok {
				if e, ok := d.DB.EntriesByJA4Prefix[prefix]; ok {
					entry = e
					found = true
					matchType = "wildcard_tls"
				}
			}
		}
		if !found {
			// Try JA4T
			entry, found = d.DB.EntriesByJA4T[fingerprint]
			if found {
				fpType = "ja4t"
				matchType = "exact"
			}
		}
	}

	res := LookupResult{Entry: entry, MatchType: matchType, FingerprintType: fpType}

	if found {
		d.logger.WithFields(logrus.Fields{
			"fingerprint": fingerprint,
			"fp_type":     fpType,
			"match_type":  matchType,
			"application": entry.Application,
			"verified":    entry.Verified,
		}).Debug("JA4DB lookup hit")
		metrics.JA4DBHits.Inc()
		metrics.JA4DBHitsByFingerprintType.WithLabelValues(fpType).Inc()
		appCategory := deriveAppCategory(entry)
		metrics.JA4DBHitsByType.WithLabelValues(matchType, appCategory).Inc()
	} else {
		d.logger.WithField("fingerprint", fingerprint).Debug("JA4DB lookup miss")
		metrics.JA4DBMisses.Inc()
		metrics.JA4DBMissesByFingerprintType.WithLabelValues(fpType).Inc()
	}
	return res, found
}

func deriveAppCategory(entry JA4Entry) string {
	app := entry.GetSearchableText()
	if IsBrowserInfo(app) {
		return "browser"
	}
	if contains(app, "scanner") || contains(app, "masscan") || contains(app, "nmap") {
		return "scanner"
	}
	if contains(app, "scraper") || contains(app, "crawler") || contains(app, "bot") {
		return "scraper"
	}
	scriptKeywords := []string{"curl", "wget", "python", "httpx", "aiohttp", "go-http", "java", "okhttp", "libcurl", "requests", "node-fetch"}
	for _, kw := range scriptKeywords {
		if contains(app, kw) {
			return "script"
		}
	}
	return "unknown"
}

// IsBrowserInfo checks if the info string indicates a browser
func IsBrowserInfo(infoLower string) bool {
	browserKeywords := []string{
		"chrome", "chromium", "firefox", "safari", "edge", "edg/", "opr/", "opera", "brave", "vivaldi",
		"crios", "fxios", "android", "ios", "iphone", "ipad",
	}
	for _, kw := range browserKeywords {
		if strings.Contains(infoLower, kw) {
			if strings.Contains(infoLower, "headless") {
				continue
			}
			return true
		}
	}
	return false
}

// IsKnownBot checks if the fingerprint belongs to a known bot
func (d *Downloader) IsKnownBot(fingerprint string) bool {
	entryIface, found := d.Lookup(fingerprint)
	if !found {
		return false
	}

	entry, ok := entryIface.(JA4Entry)
	if !ok {
		return false
	}

	// Consider it a bot if it has bot-related keywords
	app := entry.Application + " " + entry.Library + " " + entry.Device
	for _, keyword := range BotKeywordsBasic {
		if contains(app, keyword) {
			metrics.JA4DBKnownBots.Inc()
			return true
		}
	}

	return false
}

// GetInfo returns information about a fingerprint if found
func (d *Downloader) GetInfo(fingerprint string) string {
	entryIface, found := d.Lookup(fingerprint)
	if !found {
		return ""
	}

	entry, ok := entryIface.(JA4Entry)
	if !ok {
		return ""
	}

	info := entry.Application
	if entry.Library != "" {
		info += " (" + entry.Library + ")"
	}
	if entry.Device != "" {
		info += " on " + entry.Device
	}
	if entry.Verified {
		info += " [verified]"
	}

	return info
}

// FindByHeadersPrefix searches for JA4H entries where the first two parts match
// This enables probabilistic matching when protocol/headers match but cookies differ
// headersPrefix format: "{protocol}_{headers_hash}" (first two parts of JA4H)
// Returns formatted info string about the matched entry
func (d *Downloader) FindByHeadersPrefix(headersPrefix string) (string, bool) {
	d.DB.mu.RLock()
	defer d.DB.mu.RUnlock()

	// Search through all JA4H entries for matching prefix
	for fingerprint, entry := range d.DB.EntriesByJA4H {
		// Check if this fingerprint starts with the headers prefix
		if strings.HasPrefix(fingerprint, headersPrefix+"_") {
			d.logger.WithFields(logrus.Fields{
				"headers_prefix": headersPrefix,
				"matched_fp":     fingerprint,
				"application":    entry.Application,
			}).Debug("JA4H partial match found (same headers)")

			// Format info string
			info := entry.Application
			if entry.Library != "" {
				info += " (" + entry.Library + ")"
			}
			if entry.Device != "" {
				info += " on " + entry.Device
			}
			if entry.Verified {
				info += " [verified]"
			}

			// Return the first match as a probabilistic indicator
			return info, true
		}
	}

	return "", false
}

// loadFromCache loads the database from local cache
func (d *Downloader) loadFromCache() error {
	data, err := os.ReadFile(d.CachePath)
	if err != nil {
		return err
	}

	// Cache stores array format (same as API response)
	var entries []JA4Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("failed to parse cache: %w", err)
	}

	if len(entries) == 0 {
		return fmt.Errorf("cache file is empty")
	}

	// Convert to maps for fast lookups - separate maps for each fingerprint type
	entriesMap := make(map[string]JA4Entry)
	entriesByJA4Prefix := make(map[string]JA4Entry)
	entriesByJA4H := make(map[string]JA4Entry)
	entriesByJA4HPrefix := make(map[string]JA4Entry)
	entriesByJA4T := make(map[string]JA4Entry)

	for _, entry := range entries {
		if entry.JA4Fingerprint != "" {
			entriesMap[entry.JA4Fingerprint] = entry
			if prefix, ok := ja4WildcardPrefix(entry.JA4Fingerprint); ok {
				if _, exists := entriesByJA4Prefix[prefix]; !exists {
					entriesByJA4Prefix[prefix] = entry
				}
			}
		}
		if entry.JA4HFingerprint != "" {
			entriesByJA4H[entry.JA4HFingerprint] = entry
			if parts := strings.Split(entry.JA4HFingerprint, "_"); len(parts) >= 2 {
				prefix := parts[0] + "_" + parts[1]
				if _, exists := entriesByJA4HPrefix[prefix]; !exists {
					entriesByJA4HPrefix[prefix] = entry
				}
			}
		}
		if entry.JA4TFingerprint != "" {
			entriesByJA4T[entry.JA4TFingerprint] = entry
		}
	}

	d.DB.mu.Lock()
	d.DB.Entries = entriesMap
	d.DB.EntriesByJA4Prefix = entriesByJA4Prefix
	d.DB.EntriesByJA4H = entriesByJA4H
	d.DB.EntriesByJA4HPrefix = entriesByJA4HPrefix
	d.DB.EntriesByJA4T = entriesByJA4T
	d.DB.LastUpdated = time.Now() // Mark as loaded now
	d.DB.Source = "cache"
	d.DB.mu.Unlock()

	d.logger.WithFields(logrus.Fields{
		"ja4_entries":  len(entriesMap),
		"ja4h_entries": len(entriesByJA4H),
		"ja4t_entries": len(entriesByJA4T),
	}).Info("JA4 database loaded from cache")

	return nil
}

// saveToCache saves the database to local cache (as array format)
func (d *Downloader) saveToCache(entries []JA4Entry) error {
	if len(entries) == 0 {
		return fmt.Errorf("refusing to save empty database")
	}

	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}

	// Write to temp file first, then rename (atomic)
	tmpPath := d.CachePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, d.CachePath); err != nil {
		return err
	}

	d.logger.WithFields(logrus.Fields{
		"entries":  len(entries),
		"filesize": len(data),
	}).Info("JA4 database saved to cache")

	return nil
}

// Stats returns statistics about the database
func (d *Downloader) Stats() map[string]interface{} {
	d.DB.mu.RLock()
	defer d.DB.mu.RUnlock()

	return map[string]interface{}{
		"ja4_entries":  len(d.DB.Entries),
		"ja4h_entries": len(d.DB.EntriesByJA4H),
		"last_updated": d.DB.LastUpdated,
		"version":      d.DB.Version,
		"source":       d.DB.Source,
		"cache_path":   d.CachePath,
		"update_age":   time.Since(d.DB.LastUpdated).String(),
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
