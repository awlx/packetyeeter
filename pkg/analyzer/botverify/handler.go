package botverify

import (
	"net"

	"github.com/sirupsen/logrus"

	aidetection "PacketYeeter/pkg/analyzer/aidetection"
	reputation "PacketYeeter/pkg/analyzer/reputation"
	metrics "PacketYeeter/pkg/metrics"
)

// Handler provides unified bot verification handling for both DNS-verified bots
// and AI crawlers, with automatic reputation management and signal emission.
type Handler struct {
	verifier      *Verifier
	aiCrawlerReg  *AICrawlerRegistry
	signalBuilder *aidetection.SignalBuilder
	reputationMgr *reputation.Engine
}

// NewHandler creates a new bot verification handler
func NewHandler(verifier *Verifier, aiCrawlerReg *AICrawlerRegistry, signalBuilder *aidetection.SignalBuilder, reputationMgr *reputation.Engine) *Handler {
	return &Handler{
		verifier:      verifier,
		aiCrawlerReg:  aiCrawlerReg,
		signalBuilder: signalBuilder,
		reputationMgr: reputationMgr,
	}
}

// VerifyResult contains the result of bot verification
type VerifyResult struct {
	IsVerified      bool
	BotType         BotType
	CrawlerType     string
	ErrorMessage    string
	IsAICrawler     bool
	IsImpersonation bool
}

// VerifyBot performs comprehensive bot verification including DNS-based and AI crawler checks
func (h *Handler) VerifyBot(ip net.IP, userAgent, asn, org string) *VerifyResult {
	result := &VerifyResult{}

	// Skip if no user agent
	if userAgent == "" {
		return result
	}

	// Check AI crawlers first (OpenAI, Amazon, etc.)
	if h.aiCrawlerReg != nil {
		isVerified, crawlerType := h.aiCrawlerReg.VerifyAICrawler(ip, userAgent)
		if isVerified {
			result.IsVerified = true
			result.IsAICrawler = true
			result.CrawlerType = string(crawlerType)
			result.BotType = BotTypeUnknown // AI crawlers don't use BotType

			metrics.AIVerificationResults.WithLabelValues("verified").Inc()
			metrics.AIDetectionsByBotCategory.WithLabelValues(string(aidetection.BotCategoryAICrawlerVerified)).Inc()

			logrus.WithFields(logrus.Fields{
				"ip":           ip.String(),
				"crawler_type": crawlerType,
				"user_agent":   userAgent,
				"asn":          asn,
				"org":          org,
			}).Info("Verified AI crawler allowed")

			// Emit positive signal for verified AI crawler
			if h.signalBuilder != nil {
				h.signalBuilder.Emit(aidetection.Signal{
					Type:   aidetection.SignalBotUA,
					Source: aidetection.SourceSPOE,
					IP:     ip,
					ASN:    asn,
					Org:    org,
					Weight: -10.0, // Negative weight = verified/good behavior
					Metadata: map[string]interface{}{
						"crawler_type": crawlerType,
						"bot_category": aidetection.BotCategoryAICrawlerVerified,
						"user_agent":   userAgent,
						"verified":     true,
					},
				})
			}

			return result
		}

		// Check for AI crawler impersonation
		if crawlerType, hasUA := h.aiCrawlerReg.MatchUserAgent(userAgent); hasUA {
			// Exempt known ASNs from impersonation check (Amazon uses IPs not in their published list)
			trustedASNs := map[string]AICrawlerType{
				"AS14618": AICrawlerAmazonBot, // Amazon.com
				"AS16509": AICrawlerAmazonBot, // Amazon AWS
			}

			// If from trusted ASN for this crawler, allow it
			if expectedType, isTrusted := trustedASNs[asn]; isTrusted && expectedType == crawlerType {
				result.IsVerified = true
				result.IsAICrawler = true
				result.CrawlerType = string(crawlerType)

				logrus.WithFields(logrus.Fields{
					"ip":           ip.String(),
					"crawler_type": crawlerType,
					"asn":          asn,
					"org":          org,
				}).Debug("AI crawler allowed via ASN trust (not in published IP list)")

				return result
			}

			result.IsImpersonation = true
			result.CrawlerType = string(crawlerType)
			result.ErrorMessage = "AI crawler impersonation: " + string(crawlerType)

			metrics.AIVerificationResults.WithLabelValues("failed").Inc()

			logrus.WithFields(logrus.Fields{
				"ip":           ip.String(),
				"crawler_type": crawlerType,
				"user_agent":   userAgent,
				"asn":          asn,
				"org":          org,
			}).Warn("AI crawler impersonation detected")

			// Penalize impersonation
			if h.reputationMgr != nil {
				h.reputationMgr.Penalize(ip.String(), reputation.TypeIP, 40.0, "AI crawler impersonation: "+string(crawlerType))
				metrics.SPOEAnomalyEvents.Inc()
			}

			// Emit signal for impersonation
			if h.signalBuilder != nil {
				h.signalBuilder.Emit(aidetection.Signal{
					Type:   aidetection.SignalBotUA,
					Source: aidetection.SourceSPOE,
					IP:     ip,
					ASN:    asn,
					Org:    org,
					Weight: 25.0, // High penalty for impersonation
					Metadata: map[string]interface{}{
						"crawler_type":  crawlerType,
						"bot_category":  aidetection.BotCategoryAICrawlerUnknown,
						"user_agent":    userAgent,
						"impersonation": true,
					},
				})
			}

			return result
		}
	}

	// Check DNS-verified bots (Googlebot, Bingbot, etc.)
	if h.verifier != nil {
		dnsResult := h.verifier.Verify(ip, userAgent)
		result.BotType = dnsResult.BotType

		// Only track metrics if we detected a bot pattern (not regular users)
		if dnsResult.BotType != BotTypeUnknown {
			metrics.BotVerificationAttempts.WithLabelValues(string(dnsResult.BotType)).Inc()

			if dnsResult.IsVerified {
				result.IsVerified = true
				metrics.BotVerificationSuccess.WithLabelValues(string(dnsResult.BotType)).Inc()
				metrics.AIVerificationResults.WithLabelValues("verified").Inc()

				// Categorize verified bot
				botCategory := aidetection.BotCategorySearchEngine
				switch dnsResult.BotType {
				case "googlebot", "bingbot", "baiduspider", "yandexbot":
					botCategory = aidetection.BotCategorySearchEngine
				case "facebookbot", "twitterbot", "slackbot":
					botCategory = aidetection.BotCategoryLegitimate // Social media link preview bots
				default:
					botCategory = aidetection.BotCategoryLegitimate
				}
				metrics.AIDetectionsByBotCategory.WithLabelValues(string(botCategory)).Inc()

				logrus.WithFields(logrus.Fields{
					"ip":           ip.String(),
					"bot_type":     dnsResult.BotType,
					"bot_category": botCategory,
					"user_agent":   userAgent,
					"reverse_dns":  dnsResult.ReverseDNS,
					"forward_dns":  dnsResult.ForwardDNS,
					"asn":          asn,
					"org":          org,
				}).Info("Verified bot allowed")

				// Emit positive signal for verified bot
				if h.signalBuilder != nil {
					h.signalBuilder.Emit(aidetection.Signal{
						Type:   aidetection.SignalBotUA,
						Source: aidetection.SourceSPOE,
						IP:     ip,
						ASN:    asn,
						Org:    org,
						Weight: -5.0, // Negative weight = verified/good behavior
						Metadata: map[string]interface{}{
							"bot_type":     dnsResult.BotType,
							"bot_category": botCategory,
							"user_agent":   userAgent,
							"verified":     true,
							"reverse_dns":  dnsResult.ReverseDNS,
							"forward_dns":  dnsResult.ForwardDNS,
						},
					})
				}

				return result
			} else {
				// Known bot pattern but failed verification (impersonation)
				result.IsImpersonation = true
				result.ErrorMessage = dnsResult.ErrorMessage

				metrics.BotVerificationFailures.WithLabelValues(string(dnsResult.BotType), dnsResult.ErrorMessage).Inc()

				logrus.WithFields(logrus.Fields{
					"ip":         ip.String(),
					"user_agent": userAgent,
					"bot_type":   dnsResult.BotType,
					"error":      dnsResult.ErrorMessage,
					"asn":        asn,
					"org":        org,
				}).Warn("Bot impersonation detected")

				// Penalize bot impersonation attempts heavily
				if h.reputationMgr != nil {
					penalty := 50.0
					h.reputationMgr.Penalize(ip.String(), reputation.TypeIP, penalty, "Bot impersonation: "+string(dnsResult.BotType))
				}

				return result
			}
		}
	}

	return result
}
