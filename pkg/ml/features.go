package ml

import (
	"math"
	"sort"
	"strings"
	"time"

	"PacketYeeter/pkg/analyzer/aidetection"
)

// AdvancedFeatureExtractor extracts 126 features from event history
// - Temporal: 25 features (request timing, bursts)
// - Path: 20 features (diversity, enumeration patterns)
// - Header: 25 features (consistency, User-Agent analysis)
// - Signal: 25 features (HTTP 404/403 tracking + status code analysis)
// - Fingerprint: 10 features (JA4/JA4H/JA4T diversity and consistency)
// - Behavioral: 10 features (pre/post detection changes)
// - Original: 5 features (baseline detection metrics)
type AdvancedFeatureExtractor struct{}

// ExtractTemporalFeatures extracts timing and burst patterns (25 features)
func (afe *AdvancedFeatureExtractor) ExtractTemporalFeatures(snapshot aidetection.EventHistorySnapshot) []float32 {
	features := make([]float32, 25)

	if len(snapshot.Timestamps) < 2 {
		return features // All zeros
	}

	// Calculate inter-request gaps
	gaps := make([]float64, 0, len(snapshot.Timestamps)-1)
	for i := 1; i < len(snapshot.Timestamps); i++ {
		gap := snapshot.Timestamps[i].Sub(snapshot.Timestamps[i-1]).Seconds()
		gaps = append(gaps, gap)
	}

	if len(gaps) == 0 {
		return features
	}

	duration := snapshot.Timestamps[len(snapshot.Timestamps)-1].Sub(snapshot.Timestamps[0]).Seconds()

	// Basic statistics
	avgGap := mean(gaps)
	stdGap := stdDev(gaps, avgGap)
	minGap := minFloat(gaps)
	maxGap := maxFloat(gaps)
	medianGap := median(gaps)

	// Percentiles
	p25 := percentile(gaps, 25)
	p75 := percentile(gaps, 75)
	p90 := percentile(gaps, 90)
	p95 := percentile(gaps, 95)
	p99 := percentile(gaps, 99)

	// Burst coefficient
	burstCoef := float32(0)
	if avgGap > 0 {
		burstCoef = float32(stdGap / avgGap)
	}

	// Rates
	rps := float32(len(snapshot.Events)) / float32(duration)
	if duration == 0 {
		rps = 0
	}
	rpm := rps * 60

	// Gap counts
	gapsUnder10ms := countIf(gaps, func(g float64) bool { return g < 0.01 })
	gapsUnder100ms := countIf(gaps, func(g float64) bool { return g < 0.1 })
	gapsOver1s := countIf(gaps, func(g float64) bool { return g > 1.0 })
	gapsOver5s := countIf(gaps, func(g float64) bool { return g > 5.0 })

	// Peak rates (sliding window)
	peakRate1s := maxRate(snapshot.Timestamps, 1.0)
	peakRate5s := maxRate(snapshot.Timestamps, 5.0)

	// First/last minute counts
	firstMin := snapshot.Timestamps[0].Add(60 * time.Second)
	lastMin := snapshot.Timestamps[len(snapshot.Timestamps)-1].Add(-60 * time.Second)
	firstMinCount := countBefore(snapshot.Timestamps, firstMin)
	lastMinCount := countAfter(snapshot.Timestamps, lastMin)

	rateAccel := float32(0)
	if firstMinCount > 0 {
		rateAccel = float32(lastMinCount-firstMinCount) / float32(firstMinCount)
	}

	// Timing regularity (bot indicator)
	timingRegularity := float32(0)
	if burstCoef < 0.1 && avgGap > 0 {
		timingRegularity = 1.0
	}

	// Pack features
	features[0] = float32(len(snapshot.Events))
	features[1] = float32(duration)
	features[2] = rps
	features[3] = rpm
	features[4] = float32(avgGap)
	features[5] = float32(stdGap)
	features[6] = float32(minGap)
	features[7] = float32(maxGap)
	features[8] = float32(medianGap)
	features[9] = burstCoef
	features[10] = float32(gapsUnder10ms)
	features[11] = float32(gapsUnder100ms)
	features[12] = float32(gapsOver1s)
	features[13] = float32(gapsOver5s)
	features[14] = float32(peakRate1s)
	features[15] = float32(peakRate5s)
	features[16] = float32(firstMinCount)
	features[17] = float32(lastMinCount)
	features[18] = rateAccel
	features[19] = timingRegularity
	features[20] = float32(p25)
	features[21] = float32(p75)
	features[22] = float32(p90)
	features[23] = float32(p95)
	features[24] = float32(p99)

	return features
}

// ExtractPathFeatures extracts path access patterns (20 features)
func (afe *AdvancedFeatureExtractor) ExtractPathFeatures(snapshot aidetection.EventHistorySnapshot) []float32 {
	features := make([]float32, 20)

	if len(snapshot.Paths) == 0 {
		return features
	}

	// Unique paths
	uniquePaths := uniqueStrings(snapshot.Paths)
	pathDiversity := float32(len(uniquePaths)) / float32(len(snapshot.Paths))

	// Enumeration detection
	hasNumericEnum := float32(0)
	hasAlphaEnum := float32(0)
	for _, path := range snapshot.Paths {
		if strings.Contains(path, "/0") || strings.Contains(path, "/1") ||
			strings.Contains(path, "/2") || strings.Contains(path, "/3") {
			hasNumericEnum = 1
		}
		if len(path) > 3 && strings.Contains(path[1:], "/a/") || strings.Contains(path[1:], "/b/") {
			hasAlphaEnum = 1
		}
	}

	// Path depths
	depths := make([]int, len(snapshot.Paths))
	for i, path := range snapshot.Paths {
		depths[i] = strings.Count(path, "/")
	}
	avgDepth := meanInt(depths)
	stdDepth := stdDevInt(depths, avgDepth)

	// Path entropy
	allChars := strings.Join(snapshot.Paths, "")
	entropy := calculateEntropy(allChars)

	// Method analysis
	methodDiversity := float32(0)
	getRatio := float32(0)
	postRatio := float32(0)
	if len(snapshot.Methods) > 0 {
		uniqueMethods := uniqueStrings(snapshot.Methods)
		methodDiversity = float32(len(uniqueMethods)) / float32(len(snapshot.Methods))

		getCount := countString(snapshot.Methods, "GET")
		postCount := countString(snapshot.Methods, "POST")
		getRatio = float32(getCount) / float32(len(snapshot.Methods))
		postRatio = float32(postCount) / float32(len(snapshot.Methods))
	}

	// Query strings
	hasQueryStrings := float32(0)
	queryCount := 0
	for _, path := range snapshot.Paths {
		if strings.Contains(path, "?") {
			hasQueryStrings = 1
			queryCount++
		}
	}
	queryDiversity := float32(0)
	if queryCount > 0 {
		queryDiversity = float32(queryCount) / float32(len(snapshot.Paths))
	}

	// Static files
	accessingStatic := float32(0)
	for _, path := range snapshot.Paths {
		if strings.HasSuffix(path, ".jpg") || strings.HasSuffix(path, ".png") ||
			strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".js") ||
			strings.HasSuffix(path, ".ico") {
			accessingStatic = 1
			break
		}
	}

	// API endpoints
	accessingAPI := float32(0)
	for _, path := range snapshot.Paths {
		if strings.Contains(path, "/api/") || strings.Contains(path, "/v1/") ||
			strings.Contains(path, "/v2/") || strings.Contains(path, "/rest/") {
			accessingAPI = 1
			break
		}
	}

	// Path repetition
	pathCounts := countStrings(snapshot.Paths)
	mostCommon := 0
	for _, count := range pathCounts {
		if count > mostCommon {
			mostCommon = count
		}
	}
	repeatRatio := float32(mostCommon) / float32(len(snapshot.Paths))

	// Path lengths
	lengths := make([]int, len(snapshot.Paths))
	for i, path := range snapshot.Paths {
		lengths[i] = len(path)
	}
	pathLengthAvg := meanInt(lengths)
	pathLengthStd := stdDevInt(lengths, pathLengthAvg)

	// Pack features
	features[0] = float32(len(uniquePaths))
	features[1] = pathDiversity
	features[2] = hasNumericEnum
	features[3] = hasAlphaEnum
	features[4] = 0 // sequential_numeric (simplified)
	features[5] = avgDepth
	features[6] = stdDepth
	features[7] = entropy
	features[8] = methodDiversity
	features[9] = getRatio
	features[10] = postRatio
	features[11] = hasQueryStrings
	features[12] = queryDiversity
	features[13] = accessingStatic
	features[14] = accessingAPI
	features[15] = repeatRatio
	features[16] = repeatRatio // most_common_ratio (same)
	features[17] = float32(len(uniqueStrings(snapshot.Methods)))
	features[18] = pathLengthAvg
	features[19] = pathLengthStd

	return features
}

// ExtractHeaderFeatures extracts header consistency patterns (25 features)
func (afe *AdvancedFeatureExtractor) ExtractHeaderFeatures(snapshot aidetection.EventHistorySnapshot) []float32 {
	features := make([]float32, 25)

	// UA consistency
	uaConsistent := float32(1)
	if len(snapshot.UserAgents) > 0 {
		if len(uniqueStrings(snapshot.UserAgents)) > 1 {
			uaConsistent = 0
		}
	}

	// Accept-Language consistency
	langConsistent := float32(1)
	if len(snapshot.AcceptLangs) > 0 {
		if len(uniqueStrings(snapshot.AcceptLangs)) > 1 {
			langConsistent = 0
		}
	}

	// Referer consistency
	refererConsistent := float32(1)
	if len(snapshot.Referers) > 0 {
		if len(uniqueStrings(snapshot.Referers)) > 1 {
			refererConsistent = 0
		}
	}

	// UA analysis
	ua := ""
	if len(snapshot.UserAgents) > 0 {
		ua = snapshot.UserAgents[0]
	}

	botKeywords := []string{"bot", "crawler", "spider", "scraper", "curl", "wget", "python",
		"java", "go-http", "axios", "requests", "selenium", "phantom", "headless", "puppeteer"}
	browserKeywords := []string{"Chrome", "Firefox", "Safari", "Edge", "Opera"}

	hasBotKw := float32(0)
	for _, kw := range botKeywords {
		if strings.Contains(strings.ToLower(ua), kw) {
			hasBotKw = 1
			break
		}
	}

	hasBrowserKw := float32(0)
	for _, kw := range browserKeywords {
		if strings.Contains(ua, kw) {
			hasBrowserKw = 1
			break
		}
	}

	hasVersion := float32(0)
	if strings.Contains(ua, ".") && len(ua) > 0 {
		hasVersion = 1
	}

	hasPlatform := float32(0)
	platforms := []string{"Windows", "Mac", "Linux", "Android", "iOS"}
	for _, p := range platforms {
		if strings.Contains(ua, p) {
			hasPlatform = 1
			break
		}
	}

	hasMozilla := float32(0)
	if strings.Contains(ua, "Mozilla/") {
		hasMozilla = 1
	}

	uaLength := float32(len(ua))
	uaWordCount := float32(len(strings.Fields(ua)))
	uaParenCount := float32(strings.Count(ua, "("))

	// UA changes
	uniqueUAs := uniqueStrings(snapshot.UserAgents)
	uaChanges := float32(len(uniqueUAs) - 1)
	if uaChanges < 0 {
		uaChanges = 0
	}

	// Lang changes
	uniqueLangs := uniqueStrings(snapshot.AcceptLangs)
	langChanges := float32(len(uniqueLangs) - 1)
	if langChanges < 0 {
		langChanges = 0
	}

	// UA length stats
	uaLengths := make([]int, len(snapshot.UserAgents))
	for i, ua := range snapshot.UserAgents {
		uaLengths[i] = len(ua)
	}
	uaAvgLen := float32(0)
	uaStdLen := float32(0)
	if len(uaLengths) > 0 {
		uaAvgLen = meanInt(uaLengths)
		uaStdLen = stdDevInt(uaLengths, uaAvgLen)
	}

	uaComplexity := uaWordCount * uaParenCount

	// Pack features
	features[0] = uaConsistent
	features[1] = langConsistent
	features[2] = refererConsistent
	features[3] = boolToFloat32(len(snapshot.AcceptLangs) == 0) // missing_accept_lang
	features[4] = hasBotKw
	features[5] = hasBrowserKw
	features[6] = hasVersion
	features[7] = hasPlatform
	features[8] = hasMozilla
	features[9] = uaLength
	features[10] = uaWordCount
	features[11] = uaParenCount
	features[12] = float32(len(uniqueUAs))
	features[13] = float32(len(uniqueLangs))
	features[14] = boolToFloat32(len(snapshot.Referers) > 0) // has_referer
	features[15] = float32(len(uniqueStrings(snapshot.Referers))) / max32(1, float32(len(snapshot.Referers)))
	features[16] = uaChanges
	features[17] = langChanges
	features[18] = uaAvgLen
	features[19] = uaStdLen
	features[20] = float32(len(snapshot.Referers))
	features[21] = float32(len(snapshot.AcceptLangs))
	features[22] = float32(len(snapshot.UserAgents))
	features[23] = boolToFloat32(len(snapshot.Referers) == 0) // missing_referer
	features[24] = uaComplexity

	return features
}

// ExtractSignalFeatures extracts signal patterns (25 features - includes HTTP error tracking + status codes)
func (afe *AdvancedFeatureExtractor) ExtractSignalFeatures(snapshot aidetection.EventHistorySnapshot) []float32 {
	features := make([]float32, 25)

	if len(snapshot.Events) == 0 {
		return features
	}

	// Count signal types
	signalCounts := make(map[aidetection.SignalType]int)
	for _, event := range snapshot.Events {
		signalCounts[event.Type]++
	}

	total := len(snapshot.Events)
	diversity := float32(len(signalCounts)) / float32(total)

	// Entropy
	entropy := float32(0)
	for _, count := range signalCounts {
		p := float64(count) / float64(total)
		if p > 0 {
			entropy += float32(-p * math.Log2(p))
		}
	}

	// Most common ratio
	mostCommon := 0
	for _, count := range signalCounts {
		if count > mostCommon {
			mostCommon = count
		}
	}
	mostCommonRatio := float32(mostCommon) / float32(total)

	// Individual signal counts
	highFreqCount := float32(signalCounts[aidetection.SignalHighFrequency])
	pathEnumCount := float32(signalCounts[aidetection.SignalPathSeqIDs])
	missingHeaderCount := float32(signalCounts[aidetection.SignalMissingAcceptLang])
	clockSkewCount := float32(signalCounts[aidetection.SignalClockSkewAnomaly])
	entropyLowCount := float32(signalCounts[aidetection.SignalEntropyLow])
	threatScoreCount := float32(signalCounts[aidetection.SignalHighThreatScore])
	uaSuspiciousCount := float32(signalCounts[aidetection.SignalSuspiciousUA])

	// HTTP error tracking signals (scanner detection)
	// HTTP error tracking signals (scanner detection)
	excessive404Count := float32(signalCounts[aidetection.SignalExcessiveNotFound])
	excessive403Count := float32(signalCounts[aidetection.SignalExcessiveForbidden])
	errorBurstCount := float32(signalCounts[aidetection.SignalErrorBurst])
	scannerIndicators := excessive404Count + excessive403Count + errorBurstCount

	// Extract TCP metadata statistics from events
	var ttlSum, windowSum, entropySum, tcpTimestampCount float32
	var ttlCount, windowCount, entropyCount int
	for _, event := range snapshot.Events {
		if event.Metadata != nil {
			if ttl, ok := event.Metadata["ttl"].(uint32); ok && ttl > 0 {
				ttlSum += float32(ttl)
				ttlCount++
			}
			if window, ok := event.Metadata["window_size"].(uint32); ok && window > 0 {
				windowSum += float32(window)
				windowCount++
			}
			if entropy, ok := event.Metadata["entropy_score"].(uint32); ok && entropy > 0 {
				entropySum += float32(entropy)
				entropyCount++
			}
			if _, ok := event.Metadata["tcp_timestamp"].(uint32); ok {
				tcpTimestampCount++
			}
		}
	}

	ttlAvg := float32(0)
	if ttlCount > 0 {
		ttlAvg = ttlSum / float32(ttlCount)
	}
	windowAvg := float32(0)
	if windowCount > 0 {
		windowAvg = windowSum / float32(windowCount)
	}
	entropyAvg := float32(0)
	if entropyCount > 0 {
		entropyAvg = entropySum / float32(entropyCount)
	}

	// Extract HTTP status codes from metadata
	var status4xxCount, status5xxCount int
	var statusCodes []uint32
	for _, event := range snapshot.Events {
		if event.Metadata != nil {
			if status, ok := event.Metadata["status_code"].(uint32); ok && status > 0 {
				statusCodes = append(statusCodes, status)
				if status >= 400 && status < 500 {
					status4xxCount++
				} else if status >= 500 && status < 600 {
					status5xxCount++
				}
			}
		}
	}

	status4xxRatio := float32(0)
	status5xxRatio := float32(0)
	statusDiversity := float32(0)
	statusErrorRatio := float32(0)
	if len(statusCodes) > 0 {
		status4xxRatio = float32(status4xxCount) / float32(len(statusCodes))
		status5xxRatio = float32(status5xxCount) / float32(len(statusCodes))
		statusErrorRatio = float32(status4xxCount+status5xxCount) / float32(len(statusCodes))

		// Status diversity
		uniqueStatuses := make(map[uint32]bool)
		for _, s := range statusCodes {
			uniqueStatuses[s] = true
		}
		statusDiversity = float32(len(uniqueStatuses)) / float32(len(statusCodes))
	}

	// Pack features (25 signal features total now)
	features[0] = diversity
	features[1] = entropy
	features[2] = mostCommonRatio
	features[3] = float32(len(signalCounts))
	features[4] = highFreqCount
	features[5] = pathEnumCount
	features[6] = missingHeaderCount
	features[7] = clockSkewCount
	features[8] = entropyLowCount
	features[9] = threatScoreCount
	features[10] = uaSuspiciousCount
	features[11] = excessive404Count
	features[12] = excessive403Count
	features[13] = errorBurstCount
	features[14] = scannerIndicators
	features[15] = ttlAvg                                       // TCP: Average TTL
	features[16] = windowAvg / 65535.0                          // TCP: Normalized window size
	features[17] = entropyAvg / 100.0                           // TCP: Normalized entropy score
	features[18] = tcpTimestampCount / max32(1, float32(total)) // TCP: Ratio with timestamps
	features[19] = float32(status4xxCount)                      // HTTP: 4xx error count
	features[20] = float32(status5xxCount)                      // HTTP: 5xx error count
	features[21] = status4xxRatio                               // HTTP: 4xx ratio
	features[22] = status5xxRatio                               // HTTP: 5xx ratio
	features[23] = statusDiversity                              // HTTP: Status code diversity
	features[24] = statusErrorRatio                             // HTTP: Overall error ratio

	return features
}

// ExtractFingerprintFeatures extracts TLS/HTTP fingerprint diversity (10 features)
func (afe *AdvancedFeatureExtractor) ExtractFingerprintFeatures(snapshot aidetection.EventHistorySnapshot, detectionJA4, detectionJA4H, detectionJA4T string) []float32 {
	features := make([]float32, 10)

	ja4Set := make(map[string]bool)
	ja4hSet := make(map[string]bool)
	ja4tSet := make(map[string]bool)

	// Collect fingerprints from events
	for _, event := range snapshot.Events {
		if event.Metadata != nil {
			if ja4, ok := event.Metadata["ja4"].(string); ok && ja4 != "" {
				ja4Set[ja4] = true
			}
			if ja4h, ok := event.Metadata["ja4h"].(string); ok && ja4h != "" {
				ja4hSet[ja4h] = true
			}
			if ja4t, ok := event.Metadata["ja4t"].(string); ok && ja4t != "" {
				ja4tSet[ja4t] = true
			}
		}
	}

	// Add detection-level fingerprints
	if detectionJA4 != "" {
		ja4Set[detectionJA4] = true
	}
	if detectionJA4H != "" {
		ja4hSet[detectionJA4H] = true
	}
	if detectionJA4T != "" {
		ja4tSet[detectionJA4T] = true
	}

	ja4Count := len(ja4Set)
	ja4hCount := len(ja4hSet)
	ja4tCount := len(ja4tSet)
	totalEvents := float32(len(snapshot.Events))
	if totalEvents == 0 {
		totalEvents = 1
	}

	// Calculate diversity (0 = all same, 1 = all different)
	ja4Diversity := float32(0)
	if ja4Count > 1 {
		ja4Diversity = float32(ja4Count) / totalEvents
		if ja4Diversity > 1 {
			ja4Diversity = 1
		}
	}

	ja4hDiversity := float32(0)
	if ja4hCount > 1 {
		ja4hDiversity = float32(ja4hCount) / totalEvents
		if ja4hDiversity > 1 {
			ja4hDiversity = 1
		}
	}

	ja4tDiversity := float32(0)
	if ja4tCount > 1 {
		ja4tDiversity = float32(ja4tCount) / totalEvents
		if ja4tDiversity > 1 {
			ja4tDiversity = 1
		}
	}

	allConsistent := 0
	if (ja4Count <= 1 || ja4Count == 0) && (ja4hCount <= 1 || ja4hCount == 0) && (ja4tCount <= 1 || ja4tCount == 0) {
		if ja4Count > 0 || ja4hCount > 0 || ja4tCount > 0 {
			allConsistent = 1
		}
	}

	features[0] = boolToFloat32(ja4Count > 0)  // fingerprint_ja4_present
	features[1] = boolToFloat32(ja4hCount > 0) // fingerprint_ja4h_present
	features[2] = boolToFloat32(ja4tCount > 0) // fingerprint_ja4t_present
	features[3] = ja4Diversity                 // fingerprint_ja4_diversity
	features[4] = ja4hDiversity                // fingerprint_ja4h_diversity
	features[5] = ja4tDiversity                // fingerprint_ja4t_diversity
	features[6] = float32(ja4Count)            // fingerprint_ja4_count
	features[7] = float32(ja4hCount)           // fingerprint_ja4h_count
	features[8] = float32(ja4tCount)           // fingerprint_ja4t_count
	features[9] = float32(allConsistent)       // fingerprint_all_consistent

	return features
}

// ExtractBehavioralFeatures extracts pre/post detection behavior changes (10 features)
func (afe *AdvancedFeatureExtractor) ExtractBehavioralFeatures(preEvents, postEvents []aidetection.SignalEvent, preTimestamps, postTimestamps []time.Time) []float32 {
	features := make([]float32, 10)

	// Create snapshots for temporal analysis
	preSnapshot := aidetection.EventHistorySnapshot{
		Events:     preEvents,
		Timestamps: preTimestamps,
	}
	postSnapshot := aidetection.EventHistorySnapshot{
		Events:     postEvents,
		Timestamps: postTimestamps,
	}

	preTemporal := afe.ExtractTemporalFeatures(preSnapshot)
	postTemporal := afe.ExtractTemporalFeatures(postSnapshot)

	// Extract rates (index 2 is requests_per_sec)
	preRate := preTemporal[2]
	postRate := postTemporal[2]

	rateChange := postRate - preRate
	rateRatio := float32(1.0)
	if preRate > 0 {
		rateRatio = postRate / preRate
	}

	// Burst coefficient change (index 9)
	burstChange := postTemporal[9] - preTemporal[9]

	changedSignificantly := float32(0)
	if math.Abs(float64(rateRatio-1.0)) > 0.5 {
		changedSignificantly = 1.0
	}

	slowedDown := float32(0)
	if rateRatio < 0.5 {
		slowedDown = 1.0
	}

	eventRatio := float32(1.0)
	if len(preEvents) > 0 {
		eventRatio = float32(len(postEvents)) / float32(len(preEvents))
	}

	// Pack features
	features[0] = preRate
	features[1] = postRate
	features[2] = rateChange
	features[3] = rateRatio
	features[4] = burstChange
	features[5] = changedSignificantly
	features[6] = float32(len(preEvents))
	features[7] = float32(len(postEvents))
	features[8] = eventRatio
	features[9] = slowedDown

	return features
}

// Helper functions

func mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func stdDev(values []float64, mean float64) float64 {
	if len(values) <= 1 {
		return 0
	}
	variance := 0.0
	for _, v := range values {
		diff := v - mean
		variance += diff * diff
	}
	return math.Sqrt(variance / float64(len(values)-1))
}

func minFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	minVal := values[0]
	for _, v := range values[1:] {
		if v < minVal {
			minVal = v
		}
	}
	return minVal
}

func maxFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	maxVal := values[0]
	for _, v := range values[1:] {
		if v > maxVal {
			maxVal = v
		}
	}
	return maxVal
}

func max32(a, b float32) float32 {
	if a > b {
		return a
	}
	return b
}

func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)

	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[mid-1] + sorted[mid]) / 2
	}
	return sorted[mid]
}

func percentile(values []float64, p int) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)

	index := float64(p) / 100.0 * float64(len(sorted)-1)
	lower := int(index)
	upper := lower + 1

	if upper >= len(sorted) {
		return sorted[len(sorted)-1]
	}

	weight := index - float64(lower)
	return sorted[lower]*(1-weight) + sorted[upper]*weight
}

func countIf(values []float64, pred func(float64) bool) int {
	count := 0
	for _, v := range values {
		if pred(v) {
			count++
		}
	}
	return count
}

func maxRate(timestamps []time.Time, windowSec float64) int {
	if len(timestamps) == 0 {
		return 0
	}

	maxCount := 0
	for i := range timestamps {
		count := 0
		for j := i; j < len(timestamps); j++ {
			if timestamps[j].Sub(timestamps[i]).Seconds() <= windowSec {
				count++
			} else {
				break
			}
		}
		if count > maxCount {
			maxCount = count
		}
	}
	return maxCount
}

func countBefore(timestamps []time.Time, cutoff time.Time) int {
	count := 0
	for _, ts := range timestamps {
		if ts.Before(cutoff) || ts.Equal(cutoff) {
			count++
		}
	}
	return count
}

func countAfter(timestamps []time.Time, cutoff time.Time) int {
	count := 0
	for _, ts := range timestamps {
		if ts.After(cutoff) || ts.Equal(cutoff) {
			count++
		}
	}
	return count
}

func uniqueStrings(strs []string) []string {
	seen := make(map[string]bool)
	unique := make([]string, 0, len(strs))
	for _, s := range strs {
		if !seen[s] {
			seen[s] = true
			unique = append(unique, s)
		}
	}
	return unique
}

func countString(strs []string, target string) int {
	count := 0
	for _, s := range strs {
		if s == target {
			count++
		}
	}
	return count
}

func countStrings(strs []string) map[string]int {
	counts := make(map[string]int)
	for _, s := range strs {
		counts[s]++
	}
	return counts
}

func meanInt(values []int) float32 {
	if len(values) == 0 {
		return 0
	}
	sum := 0
	for _, v := range values {
		sum += v
	}
	return float32(sum) / float32(len(values))
}

func stdDevInt(values []int, mean float32) float32 {
	if len(values) <= 1 {
		return 0
	}
	variance := float32(0)
	for _, v := range values {
		diff := float32(v) - mean
		variance += diff * diff
	}
	return float32(math.Sqrt(float64(variance / float32(len(values)-1))))
}

func calculateEntropy(s string) float32 {
	if len(s) == 0 {
		return 0
	}

	counts := make(map[rune]int)
	for _, c := range s {
		counts[c]++
	}

	entropy := 0.0
	total := float64(len(s))
	for _, count := range counts {
		p := float64(count) / total
		if p > 0 {
			entropy += -p * math.Log2(p)
		}
	}

	return float32(entropy)
}

func boolToFloat32(b bool) float32 {
	if b {
		return 1.0
	}
	return 0.0
}
