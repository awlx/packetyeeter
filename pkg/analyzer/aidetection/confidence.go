package aidetection

import (
	"math"
)

// CalculateConfidence computes a rule-based confidence score (0.0-1.0) for display purposes.
//
// NOTE: This function is now used ONLY for display/debugging ("Pattern" confidence in UI).
// ML confidence is the ONLY confidence used for blocking decisions.
//
// This calculates a simple heuristic confidence based on:
//   - Signal diversity
//   - Signal count
//   - High-severity signals (honeypot, known scanner, floods)
//   - Verification status
//
// This is kept lightweight since it's not used for decisions anymore.
func CalculateConfidence(
	signals []Signal,
	signalTypes map[SignalType]int,
	sources map[SignalSource]int,
	behavioralProfile *BehavioralProfile,
	verified VerificationStatus,
	reputationScore float64,
	score float64,
) float64 {
	// Base confidence starts at 0.5
	confidence := 0.5

	// Signal diversity bonus (up to +0.15)
	diversityScore := math.Min(float64(len(signalTypes))/5.0, 1.0)
	confidence += diversityScore * 0.15

	// Signal count bonus (up to +0.1)
	signalCountScore := math.Min(float64(len(signals))/10.0, 1.0)
	confidence += signalCountScore * 0.1

	// High-severity signals bonus (up to +0.2)
	highSeverityCount := signalTypes[SignalHoneypot] +
		signalTypes[SignalJA4HBotMatch] +
		signalTypes[SignalKnownScanner] +
		signalTypes[SignalICMPFlood] +
		signalTypes[SignalUDPFlood] +
		signalTypes[SignalSYNFlood]
	if highSeverityCount > 0 {
		severityScore := math.Min(float64(highSeverityCount)/3.0, 1.0)
		confidence += severityScore * 0.2
	}

	// Verification status impact
	switch verified {
	case VerificationVerified:
		confidence -= 0.15 // Verified bot (legitimate) - reduce confidence
	case VerificationFailed:
		confidence += 0.15 // Failed verification (suspicious) - increase
	}

	// Score bonus (up to +0.1)
	scoreBoost := math.Min(score/100.0, 0.1)
	confidence += scoreBoost

	// Clamp to [0.0, 1.0]
	if confidence < 0.0 {
		confidence = 0.0
	}
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// GenerateBlockReason creates a human-readable block reason
// InferCategoryFromSignals derives a non-unknown category from signal types
func InferCategoryFromSignals(signalTypes map[SignalType]int) BotCategory {
	// DDoS indicators - any flood signal or high frequency patterns
	floodSignals := signalTypes[SignalICMPFlood] + signalTypes[SignalUDPFlood] + signalTypes[SignalSYNFlood]
	if floodSignals >= 1 || signalTypes[SignalHighFrequency] > 0 || signalTypes[SignalConnectionPattern] > 0 {
		return BotCategoryDDoS
	}

	// Scanners
	if signalTypes[SignalKnownScanner] > 0 || signalTypes[SignalPortScanning] > 0 {
		return BotCategoryScanner
	}

	// Malicious fingerprints / honeypots / abuses
	if signalTypes[SignalJA4HBotMatch] > 0 || signalTypes[SignalHoneypot] > 0 || signalTypes[SignalJA4TAbuse] > 0 || signalTypes[SignalBadFlags] > 0 || signalTypes[SignalNumericSequence] > 0 || signalTypes[SignalAlphaSequence] > 0 {
		return BotCategoryMalicious
	}

	// Fallback: if we have any signals, treat as malicious to avoid unknown on block
	if len(signalTypes) > 0 {
		return BotCategoryMalicious
	}

	return BotCategoryUnknown
}

func GenerateBlockReason(
	signalTypes map[SignalType]int,
	sources map[SignalSource]int,
	category BotCategory,
	verified VerificationStatus,
	confidence float64,
	threshold float64,
	ruleConfidence float64,
	mlConfidence float64,
) string {
	reason := "AI Detection: "

	// Add category if known
	switch category {
	case BotCategoryAICrawlerVerified:
		reason += "Verified AI crawler with suspicious signals. "
	case BotCategoryAICrawlerUnknown:
		reason += "Unverified AI crawler claim. "
	case BotCategorySearchEngine:
		reason += "Search engine with suspicious patterns. "
	case BotCategorySearchUnknown:
		reason += "Unverified search engine claim. "
	case BotCategoryScanner:
		reason += "Security scanner detected. "
	case BotCategoryScript:
		reason += "Automated script detected. "
	case BotCategoryScraper:
		reason += "Content scraper detected. "
	case BotCategoryDDoS:
		reason += "DDoS bot pattern detected. "
	case BotCategoryMalicious:
		reason += "Malicious bot activity detected. "
	case BotCategoryLegitimate:
		reason += "Legitimate bot detected (monitored). "
	default:
		reason += "Suspicious bot activity detected. "
	}

	// Add verification status
	if verified == VerificationFailed {
		reason += "Bot verification failed. "
	}

	// Add top signal types
	topSignals := getTopSignalTypes(signalTypes, 3)
	if len(topSignals) > 0 {
		reason += "Signals: "
		for i, sig := range topSignals {
			if i > 0 {
				reason += ", "
			}
			reason += formatSignalTypeName(sig)
		}
		reason += ". "
	}

	// Add confidence breakdown if ML is enabled
	if mlConfidence > 0 && ruleConfidence > 0 {
		reason += "Pattern: " + formatFloat(ruleConfidence*100) + "%, "
		reason += "ML: " + formatFloat(mlConfidence*100) + "%, "
		reason += "Final: " + formatFloat(confidence*100) + "% "
		reason += "(threshold: " + formatFloat(threshold*100) + "%)"
	} else {
		// Fallback to simple display
		reason += formatFloat(confidence*100) + "% confidence (threshold: " + formatFloat(threshold*100) + "%)"
	}

	return reason
}

// getTopSignalTypes returns the most common signal types
func getTopSignalTypes(signalTypes map[SignalType]int, limit int) []SignalType {
	type sigCount struct {
		sig   SignalType
		count int
	}

	counts := make([]sigCount, 0, len(signalTypes))
	for sig, count := range signalTypes {
		counts = append(counts, sigCount{sig, count})
	}

	// Simple bubble sort for small arrays
	for i := 0; i < len(counts); i++ {
		for j := i + 1; j < len(counts); j++ {
			if counts[j].count > counts[i].count {
				counts[i], counts[j] = counts[j], counts[i]
			}
		}
	}

	result := make([]SignalType, 0, limit)
	for i := 0; i < limit && i < len(counts); i++ {
		result = append(result, counts[i].sig)
	}

	return result
}

// formatSignalTypeName converts signal type to human-readable name
func formatSignalTypeName(sig SignalType) string {
	switch sig {
	case SignalSuspiciousUA:
		return "suspicious user agent"
	case SignalMissingAcceptLang:
		return "missing accept-language"
	case SignalMissingAcceptEnc:
		return "missing accept-encoding"
	case SignalNoCookies:
		return "no cookies"
	case SignalNoReferer:
		return "no referer"
	case SignalMissingJA4H:
		return "missing JA4H"
	case SignalHoneypot:
		return "honeypot hit"
	case SignalNumericSequence:
		return "numeric sequence"
	case SignalAlphaSequence:
		return "alpha sequence"
	case SignalProxyLag:
		return "proxy lag"
	case SignalBotUA:
		return "bot user agent"
	case SignalHighLatency:
		return "high latency"
	case SignalLatencyMismatch:
		return "latency mismatch"
	case SignalHighFrequency:
		return "high frequency"
	case SignalJA4TAbuse:
		return "JA4T abuse"
	default:
		return string(sig)
	}
}

// formatFloat formats a float to 1 decimal place
func formatFloat(f float64) string {
	return formatFloatPrec(f, 1)
}

// formatFloatPrec formats a float to specified precision
func formatFloatPrec(f float64, prec int) string {
	// Simple formatting without importing fmt or strconv
	intPart := int(f)
	fracPart := int((f - float64(intPart)) * math.Pow(10, float64(prec)))
	if fracPart < 0 {
		fracPart = -fracPart
	}

	// Build string manually
	result := intToString(intPart)
	if prec > 0 {
		result += "."
		fracStr := intToString(fracPart)
		// Pad with zeros if needed
		for len(fracStr) < prec {
			fracStr = "0" + fracStr
		}
		result += fracStr
	}
	return result
}

// intToString converts int to string
func intToString(n int) string {
	if n == 0 {
		return "0"
	}

	negative := n < 0
	if negative {
		n = -n
	}

	digits := make([]byte, 0, 10)
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}

	// Reverse
	for i := 0; i < len(digits)/2; i++ {
		digits[i], digits[len(digits)-1-i] = digits[len(digits)-1-i], digits[i]
	}

	if negative {
		return "-" + string(digits)
	}
	return string(digits)
}
