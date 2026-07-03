package metrics

import (
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// Counters for blocks vs detections

	UDPBlocks = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_udp_blocks_total",
		Help: "The total number of IP addresses blocked due to UDP floods",
	})

	UDPDetections = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_udp_detections_total",
		Help: "Total UDP flood detections (not necessarily blocked)",
	})

	ICMPBlocks = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_icmp_blocks_total",
		Help: "The total number of IP addresses blocked due to ICMP floods",
	})

	ICMPDetections = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_icmp_detections_total",
		Help: "Total ICMP flood detections (not necessarily blocked)",
	})

	TCPBlocks = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_tcp_blocks_total",
		Help: "The total number of IP addresses blocked due to TCP syn floods or bad flags",
	})

	TCPDetections = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_tcp_detections_total",
		Help: "Total TCP-related detections (SYN flood, bad flags, etc.)",
	})

	HAProxyBlocks = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_haproxy_blocks_total",
		Help: "The total number of IP addresses blocked via HAProxy Peer Protocol",
	})

	HTTPDetections = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_http_detections_total",
		Help: "Total HTTP/SPOE detections",
	})

	HTTPFloodBlocks = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_http_flood_blocks_total",
		Help: "Total HTTP flood blocks",
	})

	BurstDetections = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_burst_detections_total",
		Help: "Total burst/latency anomaly detections",
	})

	HTTPRequestRateByIP = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "packetyeeter_http_requests_per_second_by_ip",
		Help: "HTTP request rate per IP (EWMA)",
	}, []string{"ip"})

	HTTPRequestRateByASN = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "packetyeeter_http_requests_per_second_by_asn",
		Help: "HTTP request rate per ASN (EWMA)",
	}, []string{"asn", "org"})

	FlagBlocks = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_tcp_bad_flags_blocks_total",
		Help: "Total blocks due to bad TCP flags",
	})

	SynFloods = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_tcp_syn_flood_blocks_total",
		Help: "Total blocks due to SYN floods",
	})

	// High Watermarks

	HighestUDPRate = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_udp_max_rate_pps",
		Help: "Highest detected UDP packet rate (pps) from a single offender",
	})

	UDPTotalRate = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_udp_total_rate_pps",
		Help: "Total UDP packet rate (pps) across offenders",
	})

	HighestICMPRate = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_icmp_max_rate_pps",
		Help: "Highest detected ICMP packet rate (pps) from a single offender",
	})

	ICMPTotalRate = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_icmp_total_rate_pps",
		Help: "Total ICMP packet rate (pps) across offenders",
	})

	// JA4T Fingerprinting

	JA4TSuspiciousEvents = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_ja4t_suspicious_total",
		Help: "Total number of suspicious activity events detected via JA4T fingerprinting",
	})

	// JA4L / Latency

	HighLatencyEvents = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_high_latency_handshakes_total",
		Help: "Total number of events where handshake latency exceeded the high threshold",
	})

	HighestLatencyMs = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_high_latency_max_ms",
		Help: "Highest detected RTT latency (ms) from a handshake",
	})

	LatencyMismatchEvents = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_latency_mismatch_total",
		Help: "Total number of events with suspicious TTL vs RTT mismatch (L3/L4 inconsistency)",
	})

	// SPOE Metrics

	SPOELatencyReports = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_spoe_reports_total",
		Help: "Total number of latency reports received via HAProxy SPOE",
	})

	SPOEClientReqTimeHistogram = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "packetyeeter_client_req_time_ms",
		Help:    "Histogram of client request time (SYN/ACK to Headers) reported by HAProxy",
		Buckets: []float64{1, 5, 10, 50, 100, 200, 500, 1000, 2000, 5000},
	})

	SPOEAnomalyEvents = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_spoe_anomaly_total",
		Help: "Total number of detected L4 vs L7 latency anomalies",
	})

	HighestProxyLagMs = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_proxy_lag_max_ms",
		Help: "Highest detected proxy lag (Protocol Latency - Network RTT)",
	})

	ProxyLagEWMAByASN = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "packetyeeter_proxy_lag_ewma_by_asn_ms",
		Help: "EWMA of proxy lag (ms) per ASN",
	}, []string{"asn", "org"})

	SPOEHandlerLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "packetyeeter_spoe_handler_seconds",
		Help:    "Time spent in SPOE handler (HAProxy request thread)",
		Buckets: []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05},
	})

	SPOEQueueDepth = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_spoe_queue_depth",
		Help: "Current depth of SPOE processing queue",
	})

	SPOEQueueDrops = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_spoe_queue_drops_total",
		Help: "Number of SPOE messages dropped due to full queue",
	})

	CollectorSignalQueueDepth = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_collector_signal_queue_depth",
		Help: "Current depth of collector signal queue",
	})

	CollectorSignalQueueDrops = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_collector_signal_queue_drops_total",
		Help: "Number of collector signals dropped due to full queue",
	})

	// DEPRECATED: Use AIDetectionsByBotCategory instead
	// Kept for backwards compatibility during migration
	AIScraperSignalsTotal     = AISignalsTotal
	AIScraperSignalsByType    = AISignalsByType
	AIScraperSignalsByASN     = AISignalsByASN
	AIScraperDetectionsTotal  = AIDetectionsTotal
	AIScraperDetectionsByASN  = AIDetectionsByASN
	AIScraperDetectionsByJA4H = AIDetectionsByJA4H
	AIScraperDetectionsByIP   = AIDetectionsByIP
	AIScraperSignalEWMAByASN  = AISignalEWMAByASN
	AIScraperSignalEWMAByJA4H = AISignalEWMAByJA4H

	// Worker processing latency (formerly handler)
	SPOEProcessingLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "packetyeeter_spoe_processing_seconds",
		Help:    "Time spent processing a SPOE message (worker)",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
	})

	// GeoIP / ASN Metrics

	LatencyByASN = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "packetyeeter_latency_by_asn_seconds",
		Help:    "Client request latency (T1-T0) by ASN and Organization",
		Buckets: []float64{0.05, 0.1, 0.2, 0.5, 1.0, 2.0},
	}, []string{"asn", "org"})

	LatencyEWMAByASN = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "packetyeeter_latency_ewma_by_asn_ms",
		Help: "EWMA of handshake latency per ASN (ms)",
	}, []string{"asn", "org"})

	AbuseByASN = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_abuse_by_asn_total",
		Help: "Total anomalies/abuse events by ASN",
	}, []string{"asn", "org", "type"})

	// AI Detection Engine Metrics (centralized)

	AISignalsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_ai_signals_total",
		Help: "Total number of AI detection signals received",
	})

	AISignalsByType = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_ai_signals_by_type_total",
		Help: "AI detection signals by type",
	}, []string{"type"})

	AISignalsBySource = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_ai_signals_by_source_total",
		Help: "AI detection signals by source",
	}, []string{"source"})

	AISignalsByASN = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_ai_signals_by_asn_total",
		Help: "AI detection signals by ASN",
	}, []string{"asn", "org", "type"})

	AIDetectionsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_ai_detections_total",
		Help: "Total number of AI detections triggered",
	})

	AIDetectionsByIP = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_ai_detections_by_ip_total",
		Help: "AI detections by IP address",
	}, []string{"ip"})

	AIDetectionsByASN = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_ai_detections_by_asn_total",
		Help: "AI detections by ASN",
	}, []string{"asn", "org"})

	AIDetectionsByJA4H = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_ai_detections_by_ja4h_total",
		Help: "AI detections by JA4H fingerprint",
	}, []string{"ja4h"})

	AIDetectionConfidence = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "packetyeeter_ai_detection_confidence",
		Help:    "Distribution of AI detection confidence scores",
		Buckets: []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0},
	})

	AIRecentDetections = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "packetyeeter_ai_recent_detections",
		Help: "Recent AI detections metadata",
	}, []string{"ip", "asn", "org", "category", "reason", "user_agent", "confidence", "threshold", "ja4h"})

	AIConfidenceThreshold = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_ai_confidence_threshold",
		Help: "Current AI confidence threshold for blocking",
	})

	AIDetectionsByAction = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_ai_detections_action_total",
		Help: "AI detections by action taken (block, dry_run, below_threshold)",
	}, []string{"action"})

	AttackCampaignDetections = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_attack_campaign_detections_total",
		Help: "Analyzer-side attack campaign detections by vector and aggregate breadth reason",
	}, []string{"vector", "reason"})

	ActiveAttackCampaigns = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_active_attack_campaigns",
		Help: "Active analyzer-side attack campaigns in the current aggregation window",
	})

	CarpetBombingDetections = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_carpet_bombing_detections_total",
		Help: "Carpet-bombing detections by vector and aggregate breadth reason",
	}, []string{"vector", "reason"})

	CampaignBaselineMultiplier = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "packetyeeter_campaign_baseline_multiplier",
		Help:    "Observed campaign signal-rate multiplier over the adaptive service baseline",
		Buckets: []float64{0.5, 1, 1.5, 2, 3, 5, 10, 20, 50},
	}, []string{"vector", "protocol", "dst_port_bucket", "enough_samples"})

	CampaignBaselineRate = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "packetyeeter_campaign_baseline_rate",
		Help: "Adaptive EWMA campaign signal baseline rate by low-cardinality service labels",
	}, []string{"vector", "protocol", "dst_port_bucket"})

	AIBlocksBySignal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_ai_blocks_by_signal_total",
		Help: "AI blocks by top contributing signal",
	}, []string{"signal"})

	AISignalEWMAByASN = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "packetyeeter_ai_signal_ewma_by_asn",
		Help: "AI signal EWMA baseline by ASN",
	}, []string{"asn", "org"})

	AISignalEWMAByJA4H = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "packetyeeter_ai_signal_ewma_by_ja4h",
		Help: "AI signal EWMA baseline by JA4H",
	}, []string{"ja4h"})

	AIEngineQueueDepth = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_ai_engine_queue_depth",
		Help: "Current depth of AI detection signal queue",
	})

	AIEngineQueueDrops = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_ai_engine_queue_drops_total",
		Help: "Total number of signals dropped due to full queue",
	})

	AISignalProcessingLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "packetyeeter_ai_signal_processing_latency_seconds",
		Help:    "Time to process an AI signal",
		Buckets: prometheus.DefBuckets,
	})

	// Bot/AI Detection Metrics (unified)
	AIDetectionsByBotCategory = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_bot_detections_by_category_total",
		Help: "Bot detections by category (ai_crawler_verified, search_engine, scanner, scraper, etc.)",
	}, []string{"category"})

	AIVerificationResults = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_bot_verification_results_total",
		Help: "DNS/PTR/JA4 bot verification results (verified, failed, skipped, unknown)",
	}, []string{"status"})

	AIBehavioralPatterns = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_bot_behavioral_patterns_total",
		Help: "Bot behavioral patterns detected (persistent, high_frequency, bursty)",
	}, []string{"pattern"})

	AIEngineWarmup = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_ai_engine_warmup",
		Help: "1 during AI engine warmup, 0 otherwise",
	})

	ASNActiveIPs = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "packetyeeter_asn_active_ips",
		Help: "Active IPs observed per ASN",
	}, []string{"asn", "org"})

	ASNAbusiveIPs = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "packetyeeter_asn_abusive_ips",
		Help: "Abusive/detected IPs per ASN",
	}, []string{"asn", "org"})

	ASNAbuseRatio = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "packetyeeter_asn_abuse_ratio",
		Help: "Abusive IP fraction per ASN",
	}, []string{"asn", "org"})

	AIConfidenceByCategory = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "packetyeeter_bot_confidence_by_category",
		Help:    "Bot detection confidence score distribution by category",
		Buckets: []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0},
	}, []string{"category"})

	// JA4 Database Metrics
	JA4DBLookups = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_ja4db_lookups_total",
		Help: "Total JA4 database lookups performed",
	})

	JA4DBLookupsByType = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_ja4db_lookups_by_type_total",
		Help: "Total JA4 database lookups by fingerprint type (ja4, ja4h, ja4t)",
	}, []string{"type"})

	JA4DBHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_ja4db_hits_total",
		Help: "Total JA4 database lookup hits (fingerprint found)",
	})

	JA4DBHitsByFingerprintType = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_ja4db_hits_by_fp_type_total",
		Help: "JA4 database hits by fingerprint type (ja4, ja4h, ja4t)",
	}, []string{"type"})

	JA4DBMisses = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_ja4db_misses_total",
		Help: "Total JA4 database lookup misses",
	})

	JA4DBMissesByFingerprintType = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_ja4db_misses_by_fp_type_total",
		Help: "JA4 database misses by fingerprint type (ja4, ja4h, ja4t)",
	}, []string{"type"})

	JA4DBLookupLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "packetyeeter_ja4db_lookup_latency_seconds",
		Help:    "JA4 database lookup latency",
		Buckets: prometheus.DefBuckets,
	})

	JA4DBMismatch = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_ja4db_mismatch_total",
		Help: "JA4/JA4H/JA4T mismatch reasons",
	}, []string{"reason"})

	JA4DBHitsByType = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_ja4db_hits_by_type_total",
		Help: "JA4 database hits by match type (exact, wildcard_c, wildcard_cd)",
	}, []string{"match_type", "app_category"})

	JA4DBKnownBots = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_ja4db_known_bots_total",
		Help: "Total known bots identified via JA4 database",
	})

	JA4DBUserAgentHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_ja4db_user_agent_hits_total",
		Help: "JA4/JA4H/JA4T matches by user agent (high cardinality; gated)",
	}, []string{"type", "match_type", "ua"})

	// Bot Verification Metrics
	BotVerificationAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_bot_verification_attempts_total",
		Help: "Total bot verification attempts by bot type",
	}, []string{"bot_type"})

	BotVerificationSuccess = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_bot_verification_success_total",
		Help: "Successful bot verifications by bot type",
	}, []string{"bot_type"})

	BotVerificationFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_bot_verification_failures_total",
		Help: "Failed bot verifications (impersonation attempts) by claimed bot type",
	}, []string{"bot_type", "failure_reason"})

	BotVerificationCacheSize = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_bot_verification_cache_size",
		Help: "Current size of bot verification cache",
	})

	// ML Model Metrics
	MLBotProbability = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_ml_bot_probability",
		Help: "Latest ML model bot probability prediction (0-1)",
	})

	MLPredictionTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_ml_predictions_total",
		Help: "Total number of ML model predictions made",
	})

	MLBotDetections = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_ml_bot_detections_total",
		Help: "Total number of bot detections by ML model",
	})

	MLModelAccuracy = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_ml_model_accuracy",
		Help: "ML model accuracy (if labeled data available)",
	})

	MLConfidenceByCategory = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "packetyeeter_ml_confidence_by_category",
		Help:    "ML confidence score distribution by predicted category",
		Buckets: []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0},
	}, []string{"category"})

	// ASN Baseline Calibration Metrics
	BaselineCalibratedASNs = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_baseline_calibrated_asns",
		Help: "Number of ASNs with sufficient baseline observations (100+)",
	})

	BaselineObservationsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_baseline_observations_total",
		Help: "Total baseline observations recorded",
	})

	BaselineAnomaliesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_baseline_anomalies_total",
		Help: "Total baseline anomalies detected (z-score > 3)",
	})

	BaselineAnomalyScore = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "packetyeeter_baseline_anomaly_zscore",
		Help:    "Distribution of baseline anomaly z-scores by metric",
		Buckets: []float64{0, 1, 2, 3, 4, 5, 7, 10, 15, 20},
	}, []string{"asn", "metric"})

	// Threat Intelligence Metrics
	ThreatIntelEnrichments = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_threat_intel_enrichments_total",
		Help: "Total number of IP enrichments performed",
	})

	ThreatIntelCacheSize = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_threat_intel_cache_size",
		Help: "Current size of threat intel enrichment cache",
	})

	ThreatIntelKnownScanners = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_threat_intel_known_scanners",
		Help: "Number of known scanners in cache",
	})

	ThreatIntelCloudIPs = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_threat_intel_cloud_ips",
		Help: "Number of cloud IPs in cache",
	})

	ThreatIntelTorExits = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_threat_intel_tor_exits",
		Help: "Number of Tor exit nodes in cache",
	})

	ThreatIntelHighThreat = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_threat_intel_high_threat_ips",
		Help: "Number of high threat score IPs in cache (score > 50)",
	})

	ThreatIntelScore = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "packetyeeter_threat_intel_score",
		Help:    "Distribution of threat intelligence scores by IP",
		Buckets: []float64{0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
	}, []string{"ip"})

	ThreatIntelInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "packetyeeter_threat_intel_info",
		Help: "Threat intel details (metadata) by IP",
	}, []string{"ip", "sources", "tags", "open_ports", "scanner", "cloud", "tor", "vpn", "threat_score"})

	ThreatIntelShodanCacheSize = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_shodan_cache_size",
		Help: "Current size of Shodan InternetDB cache",
	})

	// Path entropy metrics
	PathEntropyByIP = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "packetyeeter_http_path_entropy_by_ip",
		Help: "HTTP path entropy by IP (rolling window)",
	}, []string{"ip"})

	PathEntropySignals = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_http_path_signals_total",
		Help: "Path entropy/sequential signals",
	}, []string{"type"})

	ThreatIntelShodanLookups = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_shodan_lookups_total",
		Help: "Total number of Shodan InternetDB API calls",
	})

	ThreatIntelShodanErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_shodan_errors_total",
		Help: "Total number of Shodan API errors",
	})

	// Clock Skew Detection Metrics
	ClockSkewObservations = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_clock_skew_observations_total",
		Help: "Total number of clock skew observations recorded",
	})

	ClockSkewResets = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_clock_skew_resets_total",
		Help: "Total number of detected TCP timestamp resets (rebaselines)",
	})

	ClockSkewAnomalies = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_clock_skew_anomalies_total",
		Help: "Total number of clock skew anomalies detected",
	})

	ClockSkewPPM = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "packetyeeter_clock_skew_ppm",
		Help:    "Clock skew in parts per million by IP",
		Buckets: []float64{-1000, -500, -100, -50, -10, 0, 10, 50, 100, 500, 1000},
	}, []string{"ip"})

	ClockSkewProfiles = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_clock_skew_profiles",
		Help: "Number of active clock skew profiles being tracked",
	})

	ClockSkewChanges = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_clock_skew_changes_total",
		Help: "Total number of detected clock skew changes (possible VM migration/replay)",
	})

	// Payload Entropy Detection Metrics
	PayloadEntropyObservations = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_payload_entropy_observations_total",
		Help: "Total number of payload entropy calculations",
	})

	PayloadEntropyValue = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "packetyeeter_payload_entropy_bits",
		Help:    "Payload entropy in bits per byte by IP",
		Buckets: []float64{0, 1, 2, 3, 4, 5, 6, 7, 7.5, 7.8, 8},
	}, []string{"ip"})

	PayloadEntropyLowCount = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_payload_entropy_low_total",
		Help: "Total number of low entropy payloads detected (< 3.0 bits)",
	})

	PayloadEntropyUniformCount = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_payload_entropy_uniform_total",
		Help: "Total number of suspiciously uniform entropy payloads (7.5-8.0 bits)",
	})

	PayloadEntropyProfiles = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_payload_entropy_profiles",
		Help: "Number of active entropy profiles being tracked",
	})

	// Rate Limiting Metrics
	RateLimitExceeded = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_rate_limit_exceeded_total",
		Help: "Total number of rate limit violations",
	}, []string{"type"}) // type: ip, asn

	RateLimitActiveIPs = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_rate_limit_active_ips",
		Help: "Number of IPs seen recently by rate limiter",
	})

	RateLimitActiveASNs = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_rate_limit_active_asns",
		Help: "Number of ASNs seen recently by rate limiter",
	})

	RateLimitCurrentlyBlockedIPs = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_rate_limit_currently_blocked_ips",
		Help: "Number of IPs blocked in the last time window",
	})

	RateLimitCurrentlyBlockedASNs = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_rate_limit_currently_blocked_asns",
		Help: "Number of ASNs blocked in the last time window",
	})

	// Pattern Tracking Metrics
	PatternTrackerProfiles = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "packetyeeter_pattern_tracker_profiles",
		Help: "Number of active connection pattern profiles being tracked",
	})

	PatternDetections = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_pattern_detections_total",
		Help: "Total pattern-based detections by type",
	}, []string{"type"}) // type: ttl_anomaly, window_anomaly, port_scanning, etc.

	MLPredictionsByCategory = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "packetyeeter_ml_predictions_by_category_total",
		Help: "ML predictions by bot category",
	}, []string{"category", "is_bot"})

	MLBlocksOverridden = promauto.NewCounter(prometheus.CounterOpts{
		Name: "packetyeeter_ml_blocks_overridden_total",
		Help: "Total blocks prevented by ML model (false positive reduction)",
	})
)

var highCardinalityEnabled atomic.Bool

func init() {
	// Default off; allow env override for debugging
	if v := os.Getenv("PACKETYEETER_HIGH_CARDINALITY_METRICS"); v != "" {
		if v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes") {
			highCardinalityEnabled.Store(true)
		}
	}
}

func SetHighCardinalityEnabled(enabled bool) {
	highCardinalityEnabled.Store(enabled)
}

func IsHighCardinalityEnabled() bool {
	return highCardinalityEnabled.Load()
}

func StartMetricsServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	return server
}
