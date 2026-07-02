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
		entropy, seqNum, seqAlpha, unique, total := a.updatePathEntropy(ip, ctx.Path)
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
	chromeUA := strings.Contains(userAgent, "Chrome") || strings.Contains(userAgent, "CriOS") || strings.Contains(userAgent, "Edg/")
	if headerOrder != "" {
		parts := strings.Split(headerOrder, ",")
		if len(parts) < 5 && a.SignalBuilder != nil {
			a.SignalBuilder.EmitHeaderAnomaly(ip, asn, org, aidetection.SignalHeaderOrderAnomaly, sig.Ja4H, sig.Ja4H, sig.Ja4T, createHTTPMetadata(map[string]interface{}{
				"header_order": headerOrder,
				"count":        len(parts),
			}))
		}
		if chromeUA && !strings.Contains(strings.ToLower(headerOrder), "sec-ch-ua") && a.SignalBuilder != nil {
			a.SignalBuilder.EmitHeaderAnomaly(ip, asn, org, aidetection.SignalMissingSecCH, sig.Ja4H, sig.Ja4H, sig.Ja4T, createHTTPMetadata(nil))
		}
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

	// Bot verification using unified handler
	if a.BotHandler != nil && userAgent != "" {
		result := a.BotHandler.VerifyBot(ip, userAgent, asn, org)
		if result.IsVerified {
			// Create observation for verified bot (for training data)
			a.recordVerifiedBot(ip, userAgent, asn, org, result, sig)
			return // Don't penalize verified bots/crawlers
		}
		// Impersonation is already handled and penalized by BotHandler
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
