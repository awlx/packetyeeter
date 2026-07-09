package analyzer

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	apiv1 "PacketYeeter/api/proto/v1"
	aidetection "PacketYeeter/pkg/analyzer/aidetection"
	"PacketYeeter/pkg/analyzer/botverify"
	"PacketYeeter/pkg/analyzer/ja4db"
	reputation "PacketYeeter/pkg/analyzer/reputation"
	metrics "PacketYeeter/pkg/metrics"
)

// Pre-compiled regex patterns for performance
var (
	reCrawlee = regexp.MustCompile(`(?i)(crawlee|apify|apify_client|python-httpx|httpx|aiohttp|python-requests)`)
)

// honestCrawlerMarkers lists self-identifying crawler tokens that aren't
// already covered by ja4db.BotKeywordsExtended's generic "bot"/"crawler"/
// "spider"/"scraper" substrings (e.g. "facebookexternalhit" contains none
// of those words). Matched case-insensitively against the user agent.
var honestCrawlerMarkers = []string{"facebookexternalhit", "ia_archiver"}

// isKnownHonestUA reports whether the user agent honestly self-identifies as
// an automated client/crawler (e.g. "Mozilla/5.0 ... Chrome/W.X.Y.Z Mobile
// Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)").
// Google's and Facebook's crawlers legitimately embed a Chrome/Chromium
// version string for rendering compatibility while still honestly declaring
// themselves via a "bot"/"crawler" token or well-known product name
// elsewhere in the same string - they are not impersonating a real browser.
func isKnownHonestUA(userAgent string) bool {
	lowerUA := strings.ToLower(userAgent)
	for _, keyword := range ja4db.BotKeywordsExtended {
		if strings.Contains(lowerUA, keyword) {
			return true
		}
	}
	for _, marker := range honestCrawlerMarkers {
		if strings.Contains(lowerUA, marker) {
			return true
		}
	}
	return false
}

// isChromeFamilyUA reports whether the user agent claims to be a
// Chromium-family browser (Chrome, Chrome-on-iOS, or Edge). Used to gate
// several conservative header/TLS heuristics below to browsers that
// deterministically send certain headers/negotiate certain TLS versions,
// keeping false-positive risk low for less common but legitimate clients.
// Honest, self-identifying crawlers (Googlebot, facebookexternalhit, etc.)
// are excluded even though their UA embeds a Chrome/Chromium version string,
// since they aren't impersonating a real browser and don't reliably send
// the same headers a real Chrome/Edge session would.
func isChromeFamilyUA(userAgent string) bool {
	if isKnownHonestUA(userAgent) {
		return false
	}
	return strings.Contains(userAgent, "Chrome") || strings.Contains(userAgent, "CriOS") || strings.Contains(userAgent, "Edg/")
}

// isBlinkEngineUA reports whether the user agent claims to be a
// Chromium/Blink-engine browser (desktop or Android Chrome, or Edge) - the
// subset of isChromeFamilyUA that actually implements Client Hints
// (sec-ch-ua) and Fetch Metadata (Sec-Fetch-*) request headers. Chrome for
// iOS (CriOS) is deliberately excluded: Apple requires every iOS browser to
// use the WebKit rendering engine, and WebKit doesn't implement either
// header family (as of 2024) - a real CriOS session behaves like Safari for
// both, not like desktop/Android Chrome, so gating on isChromeFamilyUA alone
// would falsely flag every genuine Chrome-for-iOS user.
func isBlinkEngineUA(userAgent string) bool {
	if isKnownHonestUA(userAgent) || strings.Contains(userAgent, "CriOS") {
		return false
	}
	return strings.Contains(userAgent, "Chrome") || strings.Contains(userAgent, "Edg/")
}

// isMissingSecCH reports whether a claimed Blink-engine UA's header order
// doesn't include sec-ch-ua, which real desktop/Android Chrome/Edge browsers
// always send. Use blinkUA (isBlinkEngineUA), not chromeUA, since Chrome for
// iOS never sends this header despite otherwise being Chrome-family.
func isMissingSecCH(blinkUA bool, headerOrderLower string) bool {
	return blinkUA && headerOrderLower != "" && !strings.Contains(headerOrderLower, "sec-ch-ua")
}

// isMissingSecFetch reports whether a claimed Blink-engine UA is missing all
// three of Sec-Fetch-Site/Mode/Dest. Real Chromium-based browsers (Chrome
// 76+, Edge) auto-generate these on every request; they cannot be suppressed
// by client-side JS, making their total absence a strong indicator that the
// request didn't actually come from the browser the UA claims. Use blinkUA
// (isBlinkEngineUA), not chromeUA: Chrome for iOS is WebKit-based and never
// sends these headers, same as Safari.
func isMissingSecFetch(blinkUA bool, secFetchSite, secFetchMode, secFetchDest string) bool {
	return blinkUA && secFetchSite == "" && secFetchMode == "" && secFetchDest == ""
}

// isAcceptMismatch reports whether a claimed browser UA sent an empty or
// bare wildcard-only Accept header for what looks like a top-level page
// navigation. Real browsers always send a detailed, specific Accept header
// for navigations (e.g. "text/html,application/xhtml+xml,..."); scripted
// HTTP clients frequently leave it empty or default to "*/*". However, real
// browsers' fetch()/XHR calls for subresources (JSON, WASM, scripts,
// images, etc.) legitimately default to "Accept: */*" too, so this only
// fires when Sec-Fetch-Dest is absent (not sent at all - the pre-existing
// behavior, kept for clients that don't send Fetch Metadata headers) or is
// explicitly "document" (a real navigation). Any other Sec-Fetch-Dest value
// indicates a legitimate non-navigation subresource fetch and is excluded.
func isAcceptMismatch(chromeUA bool, accept, secFetchDest string) bool {
	if !chromeUA {
		return false
	}
	if secFetchDest != "" && secFetchDest != "document" {
		return false
	}
	return accept == "" || strings.TrimSpace(accept) == "*/*"
}

// isTLSVersionMismatch reports whether a claimed Chrome/Edge UA negotiated
// an outdated TLS version. Real Chrome removed TLS 1.0/1.1 support in 2020;
// a claimed Chrome/Edge UA negotiating TLS 1.0/1.1/SSLv3 is not actually
// that browser. Only meaningful when tlsVersion is non-empty (HAProxy only
// forwards it for TLS/ssl_fc requests), so this never fires for plain HTTP.
func isTLSVersionMismatch(chromeUA bool, tlsVersion string) bool {
	if !chromeUA || tlsVersion == "" {
		return false
	}
	return tlsVersion == "TLSv1.0" || tlsVersion == "TLSv1.1" || tlsVersion == "SSLv3"
}

func (a *Analyzer) processHTTPRequest(sig *apiv1.Signal, ip net.IP, asn string, cs *collectorStream) {
	ctx := sig.HttpContext
	userAgent := ctx.UserAgent
	org := "Unknown"
	if a.GeoIP != nil && ip != nil {
		_, org = a.GeoIP.LookupWithDefaults(ip)
	}

	// Helper to create base metadata with HTTP context
	createHTTPMetadata := func(extra map[string]interface{}) map[string]interface{} {
		m := make(map[string]interface{})
		if ctx.Host != "" {
			m["host"] = ctx.Host
		}
		if ctx.Method != "" {
			m["method"] = ctx.Method
		}
		if ctx.Path != "" {
			m["path"] = ctx.Path
		}
		// Connection request count (HTTP-layer keep-alive reuse count) is
		// intentionally observational-only: real users frequently make a
		// single request per connection (first visit, short session, CDN/edge
		// connection churn, HTTP/2 multiplexing quirks), so this is too noisy
		// to gate a standalone detection signal on. It's attached here purely
		// for operator visibility in the inspector API and for future model
		// training features, not to trigger blocks by itself.
		if ctx.ConnRequestCount > 0 {
			m["conn_request_count"] = ctx.ConnRequestCount
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	// Apply rate limiting for HTTP/SPOE signals
	if a.checkRateLimit(ip, asn) {
		if !a.Config.DryRun {
			metrics.HAProxyBlocks.Inc()
			metrics.HTTPFloodBlocks.Inc()
			a.ReputationHelper.PenalizeIP(ip, 10.0, "Rate limit exceeded")
			a.sendCommand(cs, &apiv1.Command{
				Type:   apiv1.CommandType_COMMAND_BLOCK_IP,
				Ip:     sig.Ip,
				Reason: "Rate limit exceeded",
			})
		}
		return
	}

	// Update HTTP rate metrics
	ipRate, asnRate := a.updateHTTPRate(ip, asn)
	metrics.HTTPDetections.Inc()
	if metrics.IsHighCardinalityEnabled() {
		metrics.HTTPRequestRateByIP.WithLabelValues(ip.String()).Set(ipRate)
	}
	if asn != "" && asn != "Unknown" {
		metrics.HTTPRequestRateByASN.WithLabelValues(asn, org).Set(asnRate)
	}

	// Path entropy tracking
	if ctx.Path != "" {
		entropy, seqNum, seqAlpha, unique, total, timingRegular := a.updatePathEntropy(ip, ctx.Path)
		if metrics.IsHighCardinalityEnabled() {
			metrics.PathEntropyByIP.WithLabelValues(ip.String()).Set(entropy)
		}
		if entropy > 0 && entropy < 1.5 && unique > 1 && total >= 20 {
			metrics.PathEntropySignals.WithLabelValues("low_entropy").Inc()
			if a.SignalBuilder != nil {
				a.SignalBuilder.EmitPathEntropy(ip, asn, org, ctx.Path, entropy, unique, total)
			}
		}
		if seqNum {
			metrics.PathEntropySignals.WithLabelValues("seq_ids").Inc()
			if a.SignalBuilder != nil {
				a.SignalBuilder.EmitSequentialPath(ip, asn, org, ctx.Path, aidetection.SignalNumericSequence, 4.0)
			}
		}
		if seqAlpha {
			metrics.PathEntropySignals.WithLabelValues("alpha_seq").Inc()
			if a.SignalBuilder != nil {
				a.SignalBuilder.EmitSequentialPath(ip, asn, org, ctx.Path, aidetection.SignalAlphaSequence, 3.0)
			}
		}
		if timingRegular {
			metrics.PathEntropySignals.WithLabelValues("timing_regular").Inc()
			if a.SignalBuilder != nil {
				a.SignalBuilder.EmitTimingRegularity(ip, asn, org, userAgent, 3.0, unique)
			}
		}
	}

	// HTTP error tracking (404/403 scanner detection)
	if ctx.StatusCode > 0 {
		count404, count403, consecutive := a.trackHTTPErrors(ip, ctx.StatusCode, ctx.Path)

		// Excessive 404 errors - likely path enumeration or vulnerability scanner
		if count404 >= 10 {
			metrics.PathEntropySignals.WithLabelValues("excessive_404").Inc()
			if a.SignalBuilder != nil {
				weight := 5.0 + float64(count404-10)*0.5 // Escalate weight with more errors
				if weight > 15.0 {
					weight = 15.0
				}
				a.SignalBuilder.EmitHTTPErrorSignal(ip, asn, org, aidetection.SignalExcessiveNotFound, weight, count404, count403, consecutive)
			}
		}

		// Excessive 403 errors - likely permission/admin panel probing
		if count403 >= 8 {
			metrics.PathEntropySignals.WithLabelValues("excessive_403").Inc()
			if a.SignalBuilder != nil {
				weight := 6.0 + float64(count403-8)*0.6 // Higher base weight for 403s
				if weight > 15.0 {
					weight = 15.0
				}
				a.SignalBuilder.EmitHTTPErrorSignal(ip, asn, org, aidetection.SignalExcessiveForbidden, weight, count404, count403, consecutive)
			}
		}

		// Burst of consecutive errors - strong scanner indicator
		if consecutive >= 15 {
			metrics.PathEntropySignals.WithLabelValues("error_burst").Inc()
			if a.SignalBuilder != nil {
				weight := 8.0 + float64(consecutive-15)*0.3
				if weight > 20.0 {
					weight = 20.0
				}
				a.SignalBuilder.EmitHTTPErrorSignal(ip, asn, org, aidetection.SignalErrorBurst, weight, count404, count403, consecutive)
			}
		}
	}

	// Bot verification using unified handler. Run this before the UA/header
	// impersonation heuristics below (crawlee regex, sec-ch, Sec-Fetch-*,
	// Accept, TLS-version mismatch): those heuristics infer impersonation
	// from a claimed browser identity, so a request already verified as a
	// known-good bot (e.g. Googlebot's Chrome-embedded rendering UA, which
	// legitimately omits Sec-Fetch-*/sends "Accept: */*") must be excluded
	// from them, not just from the JA4 fingerprint analysis further down.
	// The verifier caches per-IP results, so calling it this early adds no
	// meaningful cost on the hot path.
	if a.BotHandler != nil && userAgent != "" {
		result := a.BotHandler.VerifyBot(ip, userAgent, asn, org)
		if result.IsVerified {
			// Create observation for verified bot (for training data)
			a.recordVerifiedBot(ip, userAgent, asn, org, result, sig)
			return // Don't penalize verified bots/crawlers
		}
		// Impersonation is already handled and penalized by BotHandler
	}

	// UA heuristics
	if userAgent != "" && reCrawlee.MatchString(userAgent) {
		if a.SignalBuilder != nil {
			a.SignalBuilder.EmitBotUA(ip, asn, org, userAgent, 10.0, createHTTPMetadata(map[string]interface{}{
				"ua_pattern": "crawlee",
				"ja4h":       sig.Ja4H,
			}))
		}
	}

	// Header order & sec-ch heuristics
	headerOrder := ""
	if h, ok := sig.Metadata["header_order"]; ok {
		headerOrder = h
	}
	chromeUA := isChromeFamilyUA(userAgent)
	blinkUA := isBlinkEngineUA(userAgent)

	// JA4/JA4H fingerprint rotation check: only meaningful for requests
	// claiming a specific, deterministic browser TLS/HTTP stack. Requires
	// at least 3 distinct fingerprints in-window before firing, to tolerate
	// a couple of real users briefly sharing a NAT/proxy IP.
	if (chromeUA || blinkUA) && (sig.Ja4S != "" || sig.Ja4H != "") {
		ja4Count, ja4hCount := a.checkJA4Consistency(ip, sig.Ja4S, sig.Ja4H)
		if (ja4Count >= 3 || ja4hCount >= 3) && a.SignalBuilder != nil {
			a.SignalBuilder.EmitJA4Rotation(ip, asn, org, userAgent, 6.0, ja4Count, ja4hCount)
		}
	}

	if headerOrder != "" {
		parts := strings.Split(headerOrder, ",")
		if len(parts) < 5 && a.SignalBuilder != nil {
			a.SignalBuilder.EmitHeaderAnomaly(ip, asn, org, aidetection.SignalHeaderOrderAnomaly, sig.Ja4H, sig.Ja4H, sig.Ja4T, createHTTPMetadata(map[string]interface{}{
				"header_order": headerOrder,
				"count":        len(parts),
			}))
		}
		if isMissingSecCH(blinkUA, strings.ToLower(headerOrder)) && a.SignalBuilder != nil {
			a.SignalBuilder.EmitHeaderAnomaly(ip, asn, org, aidetection.SignalMissingSecCH, sig.Ja4H, sig.Ja4H, sig.Ja4T, createHTTPMetadata(nil))
		}
	}

	// Sec-Fetch-* heuristics: real Chromium/Blink browsers (Chrome 76+, Edge)
	// auto-generate Sec-Fetch-Site/Mode/Dest/User on every request; these are
	// stripped from JS/HTTP client control, so a claimed Blink-engine UA missing
	// them entirely is a strong indicator of a scripted client presenting a
	// spoofed UA. Gated on blinkUA, not chromeUA: Chrome for iOS (CriOS) is
	// WebKit-based and never sends these headers, same as Safari/Firefox, so
	// gating on the broader Chrome-family check would flag every real
	// Chrome-for-iOS user.
	if isMissingSecFetch(blinkUA, ctx.SecFetchSite, ctx.SecFetchMode, ctx.SecFetchDest) && a.SignalBuilder != nil {
		a.SignalBuilder.EmitHeaderAnomaly(ip, asn, org, aidetection.SignalMissingSecFetch, sig.Ja4H, sig.Ja4H, sig.Ja4T, createHTTPMetadata(nil))
	}

	// Accept header heuristics: real browsers send a specific, detailed Accept
	// header (e.g. "text/html,application/xhtml+xml,..."); scripted HTTP
	// clients frequently leave it empty or send the default wildcard "*/*".
	// Excluded for legitimate non-navigation subresource fetches (fetch()/XHR
	// for JSON, WASM, scripts, etc.), which real browsers legitimately send
	// with "Accept: */*" - see isAcceptMismatch's doc comment.
	if isAcceptMismatch(chromeUA, ctx.Accept, ctx.SecFetchDest) && a.SignalBuilder != nil {
		a.SignalBuilder.EmitHeaderAnomaly(ip, asn, org, aidetection.SignalAcceptMismatch, sig.Ja4H, sig.Ja4H, sig.Ja4T, createHTTPMetadata(map[string]interface{}{
			"accept": ctx.Accept,
		}))
	}

	// TLS version heuristics: modern browsers only ever negotiate TLS 1.2/1.3.
	// A claimed Chrome/Edge UA that actually negotiated TLS 1.0/1.1 is not the
	// browser it claims to be (real Chrome removed TLS 1.0/1.1 support in 2020).
	// Only evaluated when HAProxy actually forwarded a TLS version (ssl_fc
	// requests only), so this never fires for plain HTTP.
	if isTLSVersionMismatch(chromeUA, ctx.TlsVersion) && a.SignalBuilder != nil {
		a.SignalBuilder.EmitHeaderAnomaly(ip, asn, org, aidetection.SignalTLSVersionMismatch, sig.Ja4H, sig.Ja4H, sig.Ja4T, createHTTPMetadata(map[string]interface{}{
			"tls_version": ctx.TlsVersion,
			"tls_cipher":  ctx.TlsCipher,
		}))
	}

	logrus.WithFields(logrus.Fields{
		"ip":            ip.String(),
		"user_agent":    userAgent,
		"client_req_ms": ctx.ClientReqMs,
		"rtt_ms":        ctx.PacketRttMs,
	}).Debug("Processing HTTP request in analyzer")

	// Record SPOE latency metrics
	if ctx.ClientReqMs > 0 {
		metrics.SPOEClientReqTimeHistogram.Observe(float64(ctx.ClientReqMs))
		metrics.SPOELatencyReports.Inc()

		logrus.WithFields(logrus.Fields{
			"ip":         ip.String(),
			"client_ms":  ctx.ClientReqMs,
			"user_agent": userAgent,
		}).Debug("Recorded SPOE latency metrics")

		// Calculate proxy lag (client request time - network RTT)
		// If RTT is available from eBPF, use it for more accurate proxy lag
		// Otherwise, client_req_ms itself represents the lag (time between TCP handshake and HTTP request)
		proxyLag := float64(ctx.ClientReqMs)
		if ctx.PacketRttMs > 0 {
			proxyLag = float64(ctx.ClientReqMs) - ctx.PacketRttMs
		}

		logrus.WithFields(logrus.Fields{
			"ip":        ip.String(),
			"client_ms": ctx.ClientReqMs,
			"rtt_ms":    ctx.PacketRttMs,
			"proxy_lag": proxyLag,
		}).Debug("Calculating proxy lag")

		if proxyLag > 0 {
			// Update highest proxy lag (gauges don't have Get, just Set)
			metrics.HighestProxyLagMs.Set(proxyLag)

			// Update EWMA by ASN if available
			if asn != "" && asn != "Unknown" {
				org := "unknown"
				if a.GeoIP != nil {
					_, org = a.GeoIP.Lookup(ip)
				}
				metrics.ProxyLagEWMAByASN.WithLabelValues(asn, org).Set(proxyLag)
			}

			// Detect anomalies
			// Adaptive threshold per ASN
			ewmaLag := a.updateProxyLag(asn, proxyLag)
			base := 1000.0 // ms
			threshold := base
			if ewmaLag > 0 {
				threshold = math.Max(base, ewmaLag*3+200)
			}
			isAnomaly := false
			if ctx.PacketRttMs > 0 {
				if proxyLag > ctx.PacketRttMs*2 && proxyLag > threshold {
					isAnomaly = true
				}
			} else {
				if proxyLag > threshold {
					isAnomaly = true
				}
			}

			metrics.ProxyLagEWMAByASN.WithLabelValues(asn, org).Set(ewmaLag)

			if isAnomaly && a.shouldEmitLatencyAnomaly(ip) {
				metrics.SPOEAnomalyEvents.Inc()
				logrus.WithFields(logrus.Fields{
					"ip":          ip.String(),
					"proxy_lag":   proxyLag,
					"rtt":         ctx.PacketRttMs,
					"client_time": ctx.ClientReqMs,
					"ewma":        ewmaLag,
					"threshold":   threshold,
				}).Info("L4/L7 latency anomaly detected")

				if a.SignalBuilder != nil {
					a.SignalBuilder.EmitLatencyAnomaly(ip, asn, org, proxyLag, ctx.PacketRttMs, ewmaLag, threshold)
				}
			}
		}
	}

	// JA4/JA4H/JA4T fingerprint analysis (prefer JA4 TLS, then JA4H HTTP, then JA4T transport)
	if a.JA4DB != nil {
		fp := ""
		fpType := ""
		if sig.Ja4S != "" {
			fp, fpType = sig.Ja4S, "ja4"
		} else if sig.Ja4H != "" {
			fp, fpType = sig.Ja4H, "ja4h"
		} else if sig.Ja4T != "" {
			fp, fpType = sig.Ja4T, "ja4t"
		}

		logExact := os.Getenv("PACKETYEETER_JA4DB_LOG_EXACT") != ""

		if fp != "" {
			res, found := a.JA4DB.LookupWithTypeResult(fp, fpType)
			if found {
				entry := res.Entry
				info := a.JA4DB.GetInfo(fp) // format info string for logs/metadata
				infoLower := strings.ToLower(info)
				isBrowser := aidetection.IsBrowserInfo(infoLower)
				exactBrowser := isBrowser && res.MatchType == "exact"

				if exactBrowser {
					a.ReputationHelper.RewardBrowser(ip, fp, asn)
					logrus.WithFields(logrus.Fields{
						"component": "analyzer_service",
						"event":     "browser_exact_ja4_match",
						"ip":        ip,
						"ja4":       fp,
						"ja4h":      sig.Ja4H,
						"ja4t":      sig.Ja4T,
						"fp":        fp,
						"fp_type":   fpType,
						"asn":       asn,
						"ua":        userAgent,
					}).Info("Browser exact JA4 match: rewarded reputation, skipping bot detection")
					return
				}

				if logExact && res.MatchType == "exact" {
					entryJSON, _ := json.Marshal(entry)
					logrus.WithFields(logrus.Fields{
						"ip":          ip,
						"ja4":         fp,
						"ja4h":        sig.Ja4H,
						"ja4t":        sig.Ja4T,
						"fp":          fp,
						"fp_type":     fpType,
						"match_type":  res.MatchType,
						"application": entry.Application,
						"library":     entry.Library,
						"device":      entry.Device,
						"os":          entry.OS,
						"ua_string":   entry.UserAgentString,
						"notes":       entry.Notes,
						"verified":    entry.Verified,
						"obs_count":   entry.ObservationCount,
						"ca":          entry.CertificateAuthority,
						"entry":       string(entryJSON),
						"user_agent":  userAgent,
					}).Info("JA4DB exact match")
				}

				// Known bot heuristic (same as IsKnownBot)
				app := entry.Application + " " + entry.Library + " " + entry.Device
				isKnownBot := false
				for _, keyword := range ja4db.BotKeywordsBasic {
					if strings.Contains(strings.ToLower(app), keyword) {
						isKnownBot = true
						break
					}
				}

				if isKnownBot {
					metrics.JA4DBKnownBots.Inc()
					logrus.WithFields(logrus.Fields{
						"ip":          ip.String(),
						"ja4":         sig.Ja4H,
						"ja4h":        sig.Ja4H,
						"ja4t":        sig.Ja4T,
						"fp_type":     res.FingerprintType,
						"match_type":  res.MatchType,
						"application": info,
					}).Info("Known bot fingerprint detected")
				}

				// record UA hits (gated)
				if userAgent != "" && metrics.IsHighCardinalityEnabled() {
					metrics.JA4DBUserAgentHits.WithLabelValues(res.FingerprintType, res.MatchType, userAgent).Inc()
				}

				if a.SignalBuilder != nil {
					// Only emit when we have some JA4DB info to act on
					if info != "" || entry.Application != "" || entry.Library != "" || entry.Device != "" {
						sigType := aidetection.SignalJA4HBotMatch
						weight := 20.0
						if isBrowser {
							sigType = aidetection.SignalBrowserDetected
							weight = 1.0
						}
						a.SignalBuilder.EmitJA4Match(ip, asn, org, fp, sig.Ja4H, sig.Ja4T, sigType, weight, map[string]interface{}{
							"application": entry.Application,
							"library":     entry.Library,
							"device":      entry.Device,
							"verified":    entry.Verified,
							"obs_count":   entry.ObservationCount,
							"ja4_info":    info,
							"match_type":  res.MatchType,
							"fp_type":     res.FingerprintType,
							"user_agent":  userAgent,
						})
					}
				}
			}
		}
	}
	// User-agent analysis for bot patterns
	if userAgent != "" {
		lowerUA := strings.ToLower(userAgent)

		// Check for common bot keywords
		for _, keyword := range ja4db.BotKeywordsExtended {
			if strings.Contains(lowerUA, keyword) {
				logrus.WithFields(logrus.Fields{
					"ip":         ip.String(),
					"user_agent": userAgent,
					"keyword":    keyword,
				}).Debug("Bot keyword detected in user-agent")

				if a.SignalBuilder != nil {
					a.SignalBuilder.EmitBotUA(ip, asn, org, userAgent, 5.0, map[string]interface{}{
						"keyword": keyword,
					})
				}
				metrics.AISignalsByType.WithLabelValues("user_agent_bot_keyword").Inc()
			}
		}
	}

	// Check for missing headers (suspicious)
	if ctx.AcceptLanguage == "" {
		logrus.WithFields(logrus.Fields{
			"ip":   ip.String(),
			"host": ctx.Host,
		}).Debug("Missing Accept-Language header")

		if a.SignalBuilder != nil {
			a.SignalBuilder.EmitMissingHeader(ip, asn, org, aidetection.SignalMissingAcceptLang, userAgent, 0.5, createHTTPMetadata(nil))
		}
		metrics.AISignalsByType.WithLabelValues("missing_accept_language").Inc()
	}

	// No-cookies / no-referer heuristics: these are individually very weak
	// (most first-time page loads, bookmarked visits, and legitimate API
	// clients legitimately have neither), so they're emitted with a low
	// weight and are only ever load-bearing in verification.go's
	// categorization routes where they're required *alongside* a bot-like
	// UA, suspicious UA, or honeypot hit - never as a standalone trigger.
	if !ctx.HasCookies {
		if a.SignalBuilder != nil {
			a.SignalBuilder.EmitMissingHeader(ip, asn, org, aidetection.SignalNoCookies, userAgent, 0.5, createHTTPMetadata(nil))
		}
		metrics.AISignalsByType.WithLabelValues("no_cookies").Inc()
	}
	if ctx.Referer == "" {
		if a.SignalBuilder != nil {
			a.SignalBuilder.EmitMissingHeader(ip, asn, org, aidetection.SignalNoReferer, userAgent, 0.5, createHTTPMetadata(nil))
		}
		metrics.AISignalsByType.WithLabelValues("no_referer").Inc()
	}

	// Threat intelligence enrichment
	if a.ThreatIntel != nil {
		if enrichedInfo := a.ThreatIntel.GetEnrichedInfo(ip); enrichedInfo != nil {
			metrics.ThreatIntelEnrichments.Inc()
			if a.ThreatIntel.IsKnownScanner(ip) {
				logrus.WithFields(logrus.Fields{
					"ip": ip.String(),
				}).Info("Known scanner detected")

				if a.SignalBuilder != nil {
					a.SignalBuilder.EmitKnownScanner(ip, asn, org, enrichedInfo.ThreatScore, enrichedInfo.Tags, enrichedInfo.Sources)
				}
			}
		}
	}

	// Check reputation threshold and potentially block
	score := a.Reputation.GetScore(ip.String(), reputation.TypeIP)
	if score > a.Config.ReputationThreshold {
		shouldBlock := true
		if a.MLModel != nil {
			features := a.extractMLFeatures(ip, asn, score)
			prediction := a.MLModel.Predict(features)
			shouldBlock = prediction.IsBot && prediction.Confidence > 0.7
			if !shouldBlock {
				metrics.MLBlocksOverridden.Inc()
			}

			if shouldBlock {
				logrus.WithFields(logrus.Fields{
					"ip":            ip.String(),
					"reputation":    score,
					"ml_confidence": prediction.Confidence,
					"ml_category":   prediction.Category,
				}).Info("ML model confirmed HTTP block decision")
			} else {
				logrus.WithFields(logrus.Fields{
					"ip":            ip.String(),
					"reputation":    score,
					"ml_confidence": prediction.Confidence,
				}).Warn("ML model rejected HTTP block")
			}
		}

		if shouldBlock && !a.Config.DryRun {
			metrics.HAProxyBlocks.Inc()
			a.sendCommand(cs, &apiv1.Command{
				Type:   apiv1.CommandType_COMMAND_BLOCK_IP,
				Ip:     sig.Ip,
				Reason: fmt.Sprintf("HTTP reputation threshold exceeded: %.0f", score),
			})
		}
	}
}

// recordVerifiedBot creates an observation entry for verified legitimate bots
// This allows them to appear in the inspector and be used for ML training
func (a *Analyzer) recordVerifiedBot(ip net.IP, userAgent, asn, org string, result *botverify.VerifyResult, sig *apiv1.Signal) {
	// Create a lightweight "detection" for the verified bot
	ctx := sig.HttpContext
	botType := "verified_bot"
	if result.IsAICrawler {
		botType = "ai_crawler_" + result.CrawlerType
	} else if result.BotType != botverify.BotTypeUnknown {
		botType = "search_engine_" + string(result.BotType)
	}

	detectionEvent := aidetection.DetectionEvent{
		IP:                 ip,
		Hostname:           ctx.Host,
		Method:             ctx.Method,
		Path:               ctx.Path,
		ASN:                asn,
		Org:                org,
		UserAgent:          userAgent,
		Signals:            []aidetection.Signal{}, // No malicious signals
		SignalCount:        0,
		Score:              0,
		BotCategory:        aidetection.BotCategoryLegitimate,
		Confidence:         1.0, // 100% confident it's legitimate
		WouldBlock:         false,
		VerificationStatus: aidetection.VerificationVerified,
		DetectionTime:      time.Now(),
	}

	// Store metadata about the verified bot
	metadata := map[string]interface{}{
		"bot_type":      botType,
		"verified":      true,
		"is_ai_crawler": result.IsAICrawler,
		"user_agent":    userAgent,
	}
	if result.CrawlerType != "" {
		metadata["crawler_type"] = result.CrawlerType
	}

	// Log for visibility
	logrus.WithFields(logrus.Fields{
		"ip":         ip.String(),
		"bot_type":   botType,
		"user_agent": userAgent,
		"asn":        asn,
		"path":       ctx.Path,
	}).Debug("Verified bot observation recorded")

	// Store in engine's detection cache so it appears in the UI
	if a.AIEngine != nil {
		a.AIEngine.StoreVerifiedBotObservation(&detectionEvent)

		// Also emit to detection handlers
		for _, handler := range a.AIEngine.GetDetectionHandlers() {
			handler.HandleDetection(detectionEvent)
		}
	}

	// TODO: Could also trigger auto-recording here if we want training data
	// a.recordSession(ip.String(), &detectionEvent, metadata)
}
