package aidetection

import (
	"container/ring"
	"net"
	"strings"
	"sync"
	"time"
)

// SignalType represents the category of AI detection signal
type SignalType string

const (
	// HTTP/L7 Signals
	SignalSuspiciousUA        SignalType = "ua_suspicious"
	SignalMissingAcceptLang   SignalType = "missing_accept_language"
	SignalMissingAcceptEnc    SignalType = "missing_accept_encoding"
	SignalNoCookies           SignalType = "no_cookies"
	SignalNoReferer           SignalType = "no_referer"
	SignalMissingJA4H         SignalType = "missing_ja4h"
	SignalHoneypot            SignalType = "honeypot"
	SignalNumericSequence     SignalType = "numeric_seq"
	SignalAlphaSequence       SignalType = "alpha_seq"
	SignalProxyLag            SignalType = "proxy_lag"
	SignalBotUA               SignalType = "bot_ua"
	SignalUserAgentBotKeyword SignalType = "user_agent_bot_keyword"
	SignalJA4HBotMatch        SignalType = "ja4h_bot_match"
	SignalBrowserDetected     SignalType = "browser_detected"

	// L4/L3 Signals
	SignalHighLatency     SignalType = "high_latency"
	SignalLatencyMismatch SignalType = "latency_mismatch"
	SignalLatencyAnomaly  SignalType = "latency_anomaly"
	SignalHighFrequency   SignalType = "high_frequency"
	SignalJA4TAbuse       SignalType = "ja4t_abuse"

	// eBPF Network Pattern Signals
	SignalTTLAnomaly          SignalType = "ttl_anomaly"          // Unusual TTL values
	SignalWindowAnomaly       SignalType = "window_anomaly"       // Suspicious TCP window sizes
	SignalConnectionPattern   SignalType = "connection_pattern"   // Rapid connection/reconnection
	SignalPacketSizeUniform   SignalType = "packet_size_uniform"  // Uniform packet sizes (bot-like)
	SignalTimingPattern       SignalType = "timing_pattern"       // Mechanical timing patterns
	SignalIncompleteHandshake SignalType = "incomplete_handshake" // SYN flood patterns
	SignalTCPMetadata         SignalType = "tcp_metadata"
	SignalPortScanning        SignalType = "port_scanning"        // Sequential port access
	SignalGeoAnomaly          SignalType = "geo_anomaly"          // Geographic impossibility
	SignalConnectionReuse     SignalType = "connection_reuse"     // Unusual connection reuse patterns
	SignalClockSkewAnomaly    SignalType = "clock_skew_anomaly"   // TCP timestamp clock skew anomaly
	SignalClockSkewChange     SignalType = "clock_skew_change"    // Significant clock skew change
	SignalEntropyLow          SignalType = "entropy_low"          // Low payload entropy (templated)
	SignalEntropyHigh         SignalType = "entropy_high"         // High/uniform entropy (encrypted)
	SignalEntropyMixed        SignalType = "entropy_mixed"        // Mixed entropy patterns (bot behavior)
	SignalPathEntropyLow      SignalType = "path_entropy_low"     // Low HTTP path entropy (repetitive paths)
	SignalPathSeqIDs          SignalType = "path_seq_ids"         // Sequential numeric path IDs (alias of numeric_seq)
	SignalHeaderOrderAnomaly  SignalType = "header_order_anomaly" // Header order inconsistent with browser
	SignalMissingSecCH        SignalType = "missing_sec_ch"       // Missing sec-ch headers for browser UA
	SignalExcessiveNotFound   SignalType = "excessive_404"        // Excessive 404 errors (path enumeration)
	SignalExcessiveForbidden  SignalType = "excessive_403"        // Excessive 403 errors (permission probing)
	SignalErrorBurst          SignalType = "error_burst"          // Burst of consecutive 4xx errors (scanner)
	SignalICMPFlood           SignalType = "icmp_flood"
	SignalUDPFlood            SignalType = "udp_flood"
	SignalSYNFlood            SignalType = "syn_flood"
	SignalBadFlags            SignalType = "bad_flags"
	SignalCarpetBombing       SignalType = "carpet_bombing"
	SignalDNSReflection       SignalType = "dns_reflection"
	SignalNTPReflection       SignalType = "ntp_reflection"
	SignalSSDPReflection      SignalType = "ssdp_reflection"
	SignalCLDAPReflection     SignalType = "cldap_reflection"
	SignalMemcachedReflection SignalType = "memcached_reflection"
	SignalQUICInitialFlood    SignalType = "quic_initial_flood"
	// Threat Intelligence Signals
	SignalKnownScanner    SignalType = "known_scanner"     // IP identified as scanner by threat intel
	SignalHighThreatScore SignalType = "high_threat_score" // IP has high threat score
	SignalTorNode         SignalType = "tor_node"          // Tor exit node
	SignalVPNProxy        SignalType = "vpn_proxy"         // VPN or proxy service
)

// SignalSource indicates where the signal came from
type SignalSource string

const (
	SourceSPOE        SignalSource = "spoe"
	SourceFingerprint SignalSource = "fingerprint"
	SourceTCP         SignalSource = "tcp"
	SourceUDP         SignalSource = "udp"
	SourceICMP        SignalSource = "icmp"
)

// BotCategory represents the categorization of detected bot traffic
type BotCategory string

const (
	BotCategoryUnknown           BotCategory = "unknown"
	BotCategoryAICrawlerVerified BotCategory = "ai_crawler_verified" // Verified AI crawler (GPTBot, ClaudeBot, etc.)
	BotCategoryAICrawlerUnknown  BotCategory = "ai_crawler_unknown"  // Unverified AI crawler claim
	BotCategorySearchEngine      BotCategory = "search_engine"       // Verified search engine (Googlebot, Bingbot)
	BotCategorySearchUnknown     BotCategory = "search_unknown"      // Unverified search engine claim
	BotCategoryMonitoring        BotCategory = "monitoring"          // Monitoring/uptime services
	BotCategoryScanner           BotCategory = "scanner"             // Security scanner or vulnerability scanner
	BotCategoryScript            BotCategory = "script"              // Automated script (curl, wget, python-requests)
	BotCategoryScraper           BotCategory = "scraper"             // Content scraper
	BotCategoryDDoS              BotCategory = "ddos"                // DDoS bot pattern detected
	BotCategoryBrowser           BotCategory = "browser"             // Verified or typical browser client
	BotCategoryLegitimate        BotCategory = "legitimate"          // Verified legitimate bot (non-browser services)
	BotCategoryMalicious         BotCategory = "malicious"           // Confirmed malicious activity
)

// VerificationStatus indicates if a bot's identity has been verified
type VerificationStatus string

const (
	VerificationUnknown  VerificationStatus = "unknown"
	VerificationVerified VerificationStatus = "verified" // DNS/PTR verified
	VerificationFailed   VerificationStatus = "failed"   // Verification attempted but failed
	VerificationSkipped  VerificationStatus = "skipped"  // Verification not applicable
)

// Signal represents a single AI detection signal
type Signal struct {
	Type      SignalType
	Source    SignalSource
	IP        net.IP
	JA4       string
	JA4H      string
	JA4T      string
	ASN       string
	Org       string
	Weight    float64
	Metadata  map[string]interface{}
	Timestamp time.Time
}

// SignalEvent is a lightweight event for history tracking (no IP to save memory)
type SignalEvent struct {
	Type      SignalType
	Source    SignalSource
	Timestamp time.Time
	Metadata  map[string]interface{}
}

// DetectionEvent represents a confirmed AI detection (multiple signals aggregated)
type DetectionEvent struct {
	IP                 net.IP
	DestIP             string // Destination IP on the host (for multi-IP hosts)
	DstPort            uint32 // Destination port (80, 443, etc.)
	Hostname           string // HTTP Host header
	Method             string // HTTP method (GET, POST, etc.)
	Path               string // HTTP path
	JA4                string
	JA4H               string
	JA4T               string
	ASN                string
	Org                string
	UserAgent          string // Extracted from HTTP signals
	Signals            []Signal
	SignalCount        int
	DetectionTime      time.Time
	EWMABaseline       float64
	Confidence         float64
	Score              float64     // Sum of signal weights
	MLConfidence       float64     // ML model confidence (0-1)
	RuleConfidence     float64     // Rule-based confidence before ML adjustment
	MLCategory         BotCategory // ML-predicted bot category
	MLModelTier        string      // Which ML tier was used: "pattern", "onnx", "statistical"
	BotCategory        BotCategory
	VerificationStatus VerificationStatus
	BlockReason        string
	WouldBlock         bool                 // Whether this detection would actually block
	SignalBreakdown    map[SignalType]int   // Count by signal type
	SourceBreakdown    map[SignalSource]int // Count by source
	Reasons            []string
	Metadata           map[string]interface{} // Additional metadata (user labels, etc.)
}

// BehavioralProfile tracks behavioral patterns over time for an entity
type BehavioralProfile struct {
	EntityID        string // IP, JA4H, or ASN
	FirstSeen       time.Time
	LastSeen        time.Time
	RequestCount    uint64
	SignalCount     uint64
	DetectionCount  uint64
	SignalRate      float64     // Signals per minute
	RequestRate     float64     // Requests per minute (if tracked)
	TimeWindows     []time.Time // Track request time distribution
	SignalDiversity float64     // Number of unique signal types seen
	SourceDiversity float64     // Number of unique sources seen
	IsPersistent    bool        // Has activity spanning > 1 hour
	IsHighFrequency bool        // Request rate above threshold
	IsBursty        bool        // Irregular spacing between requests
}

// MLFeatures contains features that could be used for machine learning models
type MLFeatures struct {
	// Basic features
	SignalCount     int
	SignalRate      float64
	SignalDiversity int // Number of unique signal types
	SourceDiversity int // Number of unique sources

	// Temporal features
	TimeSpan  float64 // Seconds between first and last signal
	IsBursty  bool
	TimeOfDay int // Hour of day (0-23)
	DayOfWeek int // 0=Sunday, 6=Saturday

	// Network features
	HasASN     bool
	HasJA4H    bool
	GeoCountry string

	// Behavioral features
	RequestRate      float64
	DetectionHistory int // Previous detections for this entity
	ReputationScore  float64

	// Threat Intelligence features
	ThreatScore        float64 // 0-100 from threat intel
	IsKnownScanner     bool
	IsCloud            bool
	IsTor              bool
	IsVPN              bool
	HasVulnerabilities bool
	OpenPortCount      int
	ThreatTags         []string

	// Signal composition
	SignalTypeVector map[SignalType]int
	SourceVector     map[SignalSource]int

	// Advanced features (126-feature model)
	EventHistory *EventHistorySnapshot // Recent event history for advanced feature extraction

	// Additional fields for ML prediction
	Confidence     float64
	WouldBlock     bool
	JA4            string
	JA4H           string  // HTTP fingerprint
	JA4T           string  // TCP fingerprint
	PathCount      int     // Number of unique paths
	UserAgentCount int     // Number of unique user agents
	ASN            int     // Autonomous System Number
	AsnReputation  float64 // ASN reputation score
}

// SignalHandler processes incoming AI signals
type SignalHandler interface {
	HandleSignal(signal Signal)
}

// DetectionHandler processes confirmed detections
type DetectionHandler interface {
	HandleDetection(event DetectionEvent)
}

// CanonicalizeSignalType normalizes signal types to canonical constants
func CanonicalizeSignalType(t SignalType) SignalType {
	s := strings.ToLower(string(t))
	switch s {
	case "latency_anomaly", "latency_anom", "latency_anomally":
		return SignalLatencyAnomaly
	case "ja4h_bot_match", "ja4h-bot-match", "ja4h_bot", "ja4hbotmatch":
		return SignalJA4HBotMatch
	case "browser_detected", "browser":
		return SignalBrowserDetected
	case "user_agent_bot_keyword", "user-agent-bot-keyword", "user_agent_bot", "useragentbotkeyword":
		return SignalUserAgentBotKeyword
	case "missing_accept_language", "missing_accept_lang":
		return SignalMissingAcceptLang
	case "known_scanner", "knownscanner", "known_scanners":
		return SignalKnownScanner
	case "path_seq_ids", "pathseqids":
		return SignalNumericSequence
	case "numeric_seq", "numericseq":
		return SignalNumericSequence
	case "alpha_seq", "alphaseq":
		return SignalAlphaSequence
	case "latency_mismatch", "latencymismatch":
		return SignalLatencyMismatch
	case "tcp_metadata", "signal_tcp_metadata":
		return SignalTCPMetadata
	}
	return t
}

// SessionRecording captures full event sequence for ML training
type SessionRecording struct {
	SessionID   string // IP_timestamp
	IP          string
	StartTime   time.Time
	EndTime     time.Time
	PreEvents   []Signal        // Events before detection (up to 100)
	PostEvents  []Signal        // Events after detection (5min)
	Detection   *DetectionEvent // The detection that triggered recording
	Outcome     string          // "blocked", "allowed", "disappeared", "escalated"
	Label       string          // ML training label: "tp", "fp", "tn", "fn", or custom
	TotalEvents int
	Duration    time.Duration
}

// ActiveRecordingInfo represents a currently recording session
type ActiveRecordingInfo struct {
	IP              string        `json:"ip"`
	StartTime       time.Time     `json:"start_time"`
	Elapsed         time.Duration `json:"elapsed"`
	Remaining       time.Duration `json:"remaining"`
	EventCount      int           `json:"event_count"`
	SessionID       string        `json:"session_id"`
	InitialCategory string        `json:"initial_category"`
	Label           string        `json:"label"` // ML training label (tp/fp/tn/fn/bot/human/manual)
}

// RollingBuffer maintains pre-detection event history
type RollingBuffer struct {
	buffer *ring.Ring
	mu     sync.Mutex
}
