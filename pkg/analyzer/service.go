package analyzer

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/pprof"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/analyzer/aidetection"
	"PacketYeeter/pkg/analyzer/baseline"
	"PacketYeeter/pkg/analyzer/botverify"
	"PacketYeeter/pkg/analyzer/clockskew"
	"PacketYeeter/pkg/analyzer/entropy"
	"PacketYeeter/pkg/analyzer/ja4db"
	"PacketYeeter/pkg/analyzer/reputation"
	"PacketYeeter/pkg/analyzer/threatintel"
	"PacketYeeter/pkg/geoip"
	"PacketYeeter/pkg/metrics"
	"PacketYeeter/pkg/ml"
	"PacketYeeter/pkg/patterns"
	"PacketYeeter/pkg/ratelimit"
	"PacketYeeter/pkg/utils/ewma"
)

const (
	defaultReputationMaxEntries  = 500000
	defaultReputationMaxAge      = 24 * time.Hour
	defaultReputationASNMaxHosts = 5000
	defaultPprofAddr             = ":6060"
)

type Config struct {
	ListenAddr                   string
	MetricsAddr                  string
	InspectorAddr                string
	GeoIPASNPath                 string
	ReputationThreshold          float64
	ReputationMaxEntries         int
	ReputationMaxAge             time.Duration
	ReputationASNMaxHosts        int
	AIConfidenceThreshold        float64
	AISuspiciousScoreThreshold   float64
	AIBlockScoreThreshold        float64
	EnableHighCardinalityMetrics bool
	EnablePprof                  bool
	PprofAddr                    string
	AIWorkers                    int
	AIQueueSize                  int
	DDoSIncompleteThreshold      int
	DDoSPatternThreshold         int
	MLModelPath                  string
	DDoSTotalThreshold           int
	DDoSRequireHighFreq          bool
	DisableDDoSCategory          bool
	JA4DBCachePath               string
	StateDir                     string
	DryRun                       bool // Monitor mode - log detections but don't block
}

// Analyzer is the AI/ML analysis daemon that receives signals from collectors

type pathEvent struct {
	Path string
	Ts   time.Time
}

type pathWindow struct {
	Events         []pathEvent
	Counts         map[string]int
	Total          int
	LastNumeric    int64
	HasLastNumeric bool
	SeqStreak      int
	LastAlpha      int64
	HasLastAlpha   bool
	AlphaSeqStreak int
}

// HTTP error tracking for scanner/crawler detection
type httpErrorEvent struct {
	StatusCode uint32
	Path       string
	Ts         time.Time
}

type httpErrorWindow struct {
	Events           []httpErrorEvent
	Total            int
	NotFound404      int
	Forbidden403     int
	ConsecutiveError int // Consecutive 4xx errors
	LastStatus       uint32
}

func topSignals(breakdown map[aidetection.SignalType]int, n int) []aidetection.SignalType {
	type sigCount struct {
		sig aidetection.SignalType
		c   int
	}
	s := make([]sigCount, 0, len(breakdown))
	for k, v := range breakdown {
		s = append(s, sigCount{sig: k, c: v})
	}
	sort.Slice(s, func(i, j int) bool { return s[i].c > s[j].c })
	if len(s) > n {
		s = s[:n]
	}
	res := make([]aidetection.SignalType, 0, len(s))
	for _, sc := range s {
		res = append(res, sc.sig)
	}
	return res
}

func extractUserAgent(signals []aidetection.Signal) string {
	for _, s := range signals {
		if uaVal, ok := s.Metadata["user_agent"]; ok {
			if uaStr, ok := uaVal.(string); ok {
				return uaStr
			}
		}
	}
	return ""
}

// Analyzer is the AI/ML analysis daemon that receives signals from collectors
type Analyzer struct {
	apiv1.UnimplementedAnalyzerServiceServer

	Config Config

	// Analysis components
	AIEngine       *aidetection.Engine
	Reputation     *reputation.Engine
	JA4DB          *ja4db.Downloader
	Baseline       *baseline.BaselineCalibrator
	BotVerifier    *botverify.Verifier
	AICrawlers     *botverify.AICrawlerRegistry
	BotHandler     *botverify.Handler
	ThreatIntel    *threatintel.ThreatIntelligence
	ClockSkew      *clockskew.Analyzer
	Entropy        *entropy.EntropyAnalyzer
	GeoIP          *geoip.Provider
	PatternTracker *patterns.PatternTracker
	MLModel        *ml.ModelManager
	ModelWatcher   *ml.ModelWatcher // Watches for model file changes

	// Signal builder
	SignalBuilder *aidetection.SignalBuilder

	// Rate limiting
	ipRateLimiters  map[string]*ratelimit.TokenBucket
	asnRateLimiters map[string]*ratelimit.TokenBucket
	rateLimitersMu  sync.RWMutex
	RateLimiter     *ratelimit.Limiter

	// HTTP rate tracking (EWMA)
	httpRateByIP  map[string]*ewma.State
	httpRateByASN map[string]*ewma.State
	httpRateMu    sync.Mutex

	// Proxy lag EWMA by ASN
	proxyLagByASN map[string]*ewma.State

	// Reputation helper
	ReputationHelper *ReputationHelper

	// Latency anomaly throttle
	latencyAnomalyThrottle map[string]time.Time
	latencyMu              sync.Mutex

	// Recent block dedup
	recentBlocks   map[string]time.Time
	recentBlocksMu sync.Mutex

	// Path entropy tracking
	pathWindows map[string]*pathWindow
	pathMu      sync.Mutex

	// HTTP error tracking (404/403 scanners)
	httpErrorWindows map[string]*httpErrorWindow
	httpErrorMu      sync.Mutex

	// Connected collectors
	collectors   map[string]*collectorStream
	collectorsMu sync.RWMutex

	// gRPC server
	grpcServer *grpc.Server
	listener   net.Listener

	// Metrics server
	metricsServer *http.Server

	// Shutdown
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	startTime time.Time
}

type collectorStream struct {
	stream apiv1.AnalyzerService_StreamSignalsServer
	sendMu sync.Mutex
}

func mapProtoSignalType(t apiv1.SignalType) aidetection.SignalType {
	switch t {
	case apiv1.SignalType_SIGNAL_ICMP_FLOOD:
		return aidetection.SignalICMPFlood
	case apiv1.SignalType_SIGNAL_UDP_FLOOD:
		return aidetection.SignalUDPFlood
	case apiv1.SignalType_SIGNAL_SYN_FLOOD:
		return aidetection.SignalSYNFlood
	case apiv1.SignalType_SIGNAL_BAD_FLAGS:
		return aidetection.SignalBadFlags
	case apiv1.SignalType_SIGNAL_INCOMPLETE_HANDSHAKE:
		return aidetection.SignalIncompleteHandshake
	case apiv1.SignalType_SIGNAL_TCP_METADATA:
		return aidetection.SignalTCPMetadata
	default:
		return aidetection.SignalType(t.String())
	}
}

func New(cfg Config) (*Analyzer, error) {
	if cfg.ReputationMaxEntries == 0 {
		cfg.ReputationMaxEntries = defaultReputationMaxEntries
	}
	if cfg.ReputationMaxAge == 0 {
		cfg.ReputationMaxAge = defaultReputationMaxAge
	}
	if cfg.ReputationASNMaxHosts == 0 {
		cfg.ReputationASNMaxHosts = defaultReputationASNMaxHosts
	}
	if cfg.PprofAddr == "" {
		cfg.PprofAddr = defaultPprofAddr
	}

	ctx, cancel := context.WithCancel(context.Background())
	a := &Analyzer{
		Config:                 cfg,
		collectors:             make(map[string]*collectorStream),
		ipRateLimiters:         make(map[string]*ratelimit.TokenBucket),
		asnRateLimiters:        make(map[string]*ratelimit.TokenBucket),
		RateLimiter:            ratelimit.NewLimiter(ratelimit.DefaultConfig()),
		httpRateByIP:           make(map[string]*ewma.State),
		httpRateByASN:          make(map[string]*ewma.State),
		proxyLagByASN:          make(map[string]*ewma.State),
		latencyAnomalyThrottle: make(map[string]time.Time),
		pathWindows:            make(map[string]*pathWindow),
		httpErrorWindows:       make(map[string]*httpErrorWindow),
		recentBlocks:           make(map[string]time.Time),
		ctx:                    ctx,
		cancel:                 cancel,
		startTime:              time.Now(),
	}
	a.ReputationHelper = NewReputationHelper(nil) // Will be set during Start()
	return a, nil
}

func (a *Analyzer) Start() error {
	var err error

	metrics.SetHighCardinalityEnabled(a.Config.EnableHighCardinalityMetrics)
	if a.Config.EnableHighCardinalityMetrics {
		logrus.Warn("High-cardinality metrics enabled; may cause large scrape payloads and series explosion")
	} else {
		logrus.Debug("High-cardinality metrics disabled")
	}

	if a.Config.EnablePprof {
		go startPprof(a.Config.PprofAddr)
	}

	// Initialize GeoIP
	if a.Config.GeoIPASNPath != "" {
		a.GeoIP, err = geoip.New(a.Config.GeoIPASNPath)
		if err != nil {
			logrus.WithError(err).Warn("Failed to load GeoIP DB")
		} else {
			logrus.Info("GeoIP Database initialized")
		}
	}

	// Initialize Reputation Engine
	rep := reputation.New(30*time.Minute, 0.95, a.Config.ReputationThreshold)
	rep.SetMaxEntries(a.Config.ReputationMaxEntries)
	rep.SetMaxEntryAge(a.Config.ReputationMaxAge)
	rep.SetMaxASNHosts(a.Config.ReputationASNMaxHosts)
	a.Reputation = rep
	a.ReputationHelper = NewReputationHelper(a.Reputation)
	logrus.WithFields(logrus.Fields{
		"threshold":     a.Config.ReputationThreshold,
		"max_entries":   a.Config.ReputationMaxEntries,
		"max_age":       a.Config.ReputationMaxAge,
		"max_asn_hosts": a.Config.ReputationASNMaxHosts,
	}).Info("Reputation Engine initialized")

	// Initialize Threat Intelligence (Shodan InternetDB - free API)
	a.ThreatIntel = threatintel.NewThreatIntelligence()
	logrus.Info("Threat Intelligence Engine initialized (Shodan InternetDB)")

	// Initialize JA4 Database
	cachePath := a.Config.JA4DBCachePath
	if cachePath == "" {
		cachePath = "/var/cache/ja4db"
	}
	a.JA4DB = ja4db.NewDownloader(cachePath, logrus.StandardLogger())
	if err := a.JA4DB.Start(); err != nil {
		logrus.WithError(err).Warn("Failed to start JA4DB downloader")
	} else {
		logrus.Info("JA4 Database initialized and downloading")
	}

	// Initialize AI Detection Engine with all components
	aiCfg := aidetection.DefaultConfig()
	if a.Config.AIWorkers > 0 {
		aiCfg.Workers = a.Config.AIWorkers
	}
	if a.Config.AIQueueSize > 0 {
		aiCfg.BufferSize = a.Config.AIQueueSize
	}
	aiCfg.GeoIP = a.GeoIP
	aiCfg.Reputation = a.Reputation
	aiCfg.JA4Verifier = a.JA4DB
	aiCfg.ThreatIntel = a.ThreatIntel
	aiCfg.ConfidenceThreshold = a.Config.AIConfidenceThreshold
	aiCfg.SuspiciousScoreThreshold = a.Config.AISuspiciousScoreThreshold
	aiCfg.BlockScoreThreshold = a.Config.AIBlockScoreThreshold
	aiCfg.DDoSIncompleteThreshold = a.Config.DDoSIncompleteThreshold
	aiCfg.DDoSPatternThreshold = a.Config.DDoSPatternThreshold
	aiCfg.DDoSTotalThreshold = a.Config.DDoSTotalThreshold
	aiCfg.DDoSRequireHighFreq = a.Config.DDoSRequireHighFreq
	aiCfg.EnableDDoSCategory = !a.Config.DisableDDoSCategory
	stateDir := a.Config.StateDir
	if stateDir == "" {
		stateDir = "/var/cache/packetyeeter"
	}
	aiCfg.StatePath = filepath.Join(stateDir, "ai_asn_state.json")
	aiCfg.SessionRecordingsPath = filepath.Join(stateDir, "sessions")

	// Enable feedback loop for adaptive threshold adjustment
	aiCfg.EnableFeedback = true
	aiCfg.FeedbackConfig = aidetection.DefaultFeedbackConfig()

	// Initialize default ML model
	// Initialize ML Model - Use Hybrid Model for pattern + ONNX + fallback
	var mlModel aidetection.MLModel
	if a.Config.MLModelPath != "" {
		// Create hybrid model with ONNX + statistical fallback
		hybridModel := ml.NewHybridModel(a.Config.MLModelPath, a.Config.AIConfidenceThreshold)
		mlModel = hybridModel
		logrus.WithFields(logrus.Fields{
			"model_path": a.Config.MLModelPath,
			"threshold":  a.Config.AIConfidenceThreshold,
		}).Info("Initialized Hybrid ML Model (Pattern + ONNX + Statistical)")
	} else {
		// No ONNX path - use statistical model only
		mlModel = ml.NewSimpleThresholdModel()
		logrus.Info("Initialized Statistical ML Model (no ONNX)")
	}
	aiCfg.MLModel = mlModel

	a.AIEngine = aidetection.New(aiCfg)
	logrus.WithField("threshold", aiCfg.ConfidenceThreshold).Info("AI Detection Engine initialized")

	// Inject pattern checker into hybrid model if it's a hybrid
	if hybridModel, ok := mlModel.(*ml.HybridModel); ok && a.AIEngine != nil {
		// Wait for feedback loop to initialize, then inject pattern checker
		go func() {
			time.Sleep(100 * time.Millisecond) // Give feedback loop time to initialize
			if feedback := a.AIEngine.GetFeedbackLoop(); feedback != nil {
				hybridModel.SetPatternChecker(feedback)
				logrus.Info("Hybrid ML Model: Pattern checker connected to feedback loop")
			}
		}()
	}

	// Register detection handler to send BLOCK commands to collectors
	a.AIEngine.RegisterDetectionHandler(a)

	// Start AIEngine workers
	a.AIEngine.Start()

	// Initialize baseline calibrator
	a.Baseline = baseline.NewBaselineCalibrator(baseline.DefaultConfig())
	logrus.Info("Baseline Calibrator initialized")

	// Initialize clock skew and entropy analyzers
	a.ClockSkew = clockskew.NewAnalyzer(a.AIEngine)
	a.ClockSkew.Start()
	a.Entropy = entropy.NewEntropyAnalyzer(a.AIEngine)
	a.Entropy.Start()
	logrus.Info("Clock Skew and Entropy Analyzers initialized")

	// Initialize Bot Verification
	a.BotVerifier = botverify.NewVerifierWithGeoIP(1*time.Hour, 5*time.Second, a.GeoIP)
	a.AICrawlers = botverify.NewAICrawlerRegistry(1 * time.Hour)
	logrus.Info("Bot Verification and AI Crawler Registry initialized")

	// Initialize SignalBuilder
	a.SignalBuilder = aidetection.NewSignalBuilder(a.AIEngine)
	logrus.Info("Signal Builder initialized")

	// Initialize BotHandler (unified bot verification with reputation and signal emission)
	a.BotHandler = botverify.NewHandler(a.BotVerifier, a.AICrawlers, a.SignalBuilder, a.Reputation)
	logrus.Info("Bot Verification Handler initialized")

	// Initialize Pattern Tracker
	a.PatternTracker = patterns.NewPatternTracker(a.AIEngine)
	a.PatternTracker.StartCleanup()
	logrus.Info("Pattern Tracker initialized")

	// Initialize ML Model
	a.MLModel = ml.NewModelManager()
	logrus.Info("ML Model initialized and enabled")

	// Start model file watcher for dynamic reloading
	if a.Config.MLModelPath != "" {
		reloadFunc := func(modelPath string) error {
			// Check if primary model is an ONNX model and reload it
			if a.MLModel != nil {
				primaryModel := a.MLModel.GetPrimaryModel()
				if onnxModel, ok := primaryModel.(*ml.ONNXModel); ok {
					return onnxModel.Reload(modelPath)
				}
			}
			return nil
		}

		a.ModelWatcher = ml.NewModelWatcher(a.Config.MLModelPath, 10*time.Second, reloadFunc)
		if err := a.ModelWatcher.Start(); err != nil {
			logrus.WithError(err).Warn("Failed to start model file watcher")
		} else {
			logrus.Info("Model file watcher started - will auto-reload on changes")
		}
	}

	logrus.Info("✅ All analyzer components initialized successfully")
	// Start gRPC Server
	lis, err := net.Listen("tcp", a.Config.ListenAddr)
	if err != nil {
		return err
	}
	a.listener = lis

	var opts []grpc.ServerOption
	opts = append(opts, grpc.KeepaliveParams(keepalive.ServerParameters{
		Time:    10 * time.Second,
		Timeout: 3 * time.Second,
	}))
	opts = append(opts, grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
		MinTime:             5 * time.Second,
		PermitWithoutStream: true,
	}))

	a.grpcServer = grpc.NewServer(opts...)
	apiv1.RegisterAnalyzerServiceServer(a.grpcServer, a)

	// Start background tasks
	a.wg.Add(1)
	go a.runBaselineCalibrator()

	// Start metrics server
	a.metricsServer = metrics.StartMetricsServer(a.Config.MetricsAddr)
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		logrus.WithField("addr", a.Config.MetricsAddr).Info("Starting metrics server")
		if err := a.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logrus.WithError(err).Error("Metrics server error")
		}
	}()

	// Start inspector server (localhost-only by default)
	if a.Config.InspectorAddr != "" {
		inspectorServer := metrics.StartMetricsServer(a.Config.InspectorAddr)
		if mux, ok := inspectorServer.Handler.(*http.ServeMux); ok {
			registerInspectorHandlers(a, mux)
		}
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			logrus.WithField("addr", a.Config.InspectorAddr).Info("Starting inspector server")
			if err := inspectorServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logrus.WithError(err).Error("Inspector server error")
			}
		}()
	}

	// Threat intel metrics updater
	if a.ThreatIntel != nil {
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-a.ctx.Done():
					return
				case <-ticker.C:
					stats := a.ThreatIntel.GetStats()
					if v, ok := stats["enrichment_cache_size"].(int); ok {
						metrics.ThreatIntelCacheSize.Set(float64(v))
					}
					if v, ok := stats["known_scanners"].(int); ok {
						metrics.ThreatIntelKnownScanners.Set(float64(v))
					}
					if v, ok := stats["cloud_ips"].(int); ok {
						metrics.ThreatIntelCloudIPs.Set(float64(v))
					}
					if v, ok := stats["tor_exits"].(int); ok {
						metrics.ThreatIntelTorExits.Set(float64(v))
					}
					if v, ok := stats["high_threat_ips"].(int); ok {
						metrics.ThreatIntelHighThreat.Set(float64(v))
					}
					if v, ok := stats["shodan_cache_size"].(int); ok {
						metrics.ThreatIntelShodanCacheSize.Set(float64(v))
					}
				}
			}
		}()
	}

	// Periodic cleanup of tracking maps to prevent memory leaks
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-a.ctx.Done():
				return
			case <-ticker.C:
				a.cleanupTrackingMaps()
			}
		}
	}()

	// Start gRPC server
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		logrus.WithField("addr", a.Config.ListenAddr).Info("Starting gRPC server")
		if err := a.grpcServer.Serve(lis); err != nil {
			logrus.WithError(err).Error("gRPC server error")
		}
	}()

	return nil
}

// StreamSignals implements the bidirectional streaming RPC
func (a *Analyzer) StreamSignals(stream apiv1.AnalyzerService_StreamSignalsServer) error {
	ctx := stream.Context()
	collectorID := ctx.Value("collector-id")
	if collectorID == nil {
		collectorID = "unknown"
	}

	cs := &collectorStream{stream: stream}
	a.collectorsMu.Lock()
	a.collectors[collectorID.(string)] = cs
	a.collectorsMu.Unlock()

	defer func() {
		a.collectorsMu.Lock()
		delete(a.collectors, collectorID.(string))
		a.collectorsMu.Unlock()
	}()

	logrus.WithField("collector", collectorID).Info("Collector connected")

	signalCounts := make(map[string]int)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-a.ctx.Done():
			return nil
		case <-ticker.C:
			if len(signalCounts) > 0 {
				fields := logrus.Fields{}
				for k, v := range signalCounts {
					fields[k] = v
				}
				logrus.WithFields(fields).Info("Signal counts (last 30s)")
				signalCounts = make(map[string]int)
			}
		default:
		}

		sig, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		signalCounts[sig.Type.String()]++

		logrus.WithFields(logrus.Fields{
			"collector":   collectorID,
			"signal_type": sig.Type.String(),
			"ip":          net.IP(sig.Ip).String(),
		}).Debug("Signal received by analyzer")

		a.processSignal(sig, cs)
	}
}

func (a *Analyzer) processSignal(sig *apiv1.Signal, cs *collectorStream) {
	// Check for reputation penalty request
	if sig.Metadata != nil {
		if penaltyKey, ok := sig.Metadata["penalty_key"]; ok {
			penaltyType := sig.Metadata["penalty_type"]
			reason := sig.Metadata["penalty_reason"]
			a.Reputation.Penalize(penaltyKey, reputation.EntityType(penaltyType), sig.Weight, reason)
			return
		}
	}

	if sig.Ip == nil {
		return
	}

	ip := net.IP(sig.Ip)
	asn := "Unknown"
	if a.GeoIP != nil {
		asn, _ = a.GeoIP.LookupWithDefaults(ip)
	}

	// Trigger async threat intelligence enrichment
	if a.ThreatIntel != nil {
		a.ThreatIntel.EnrichIP(ip)
	}

	// Handle HTTP Request signals from SPOE collector
	if sig.Type == apiv1.SignalType_SIGNAL_HTTP_REQUEST && sig.HttpContext != nil {
		a.processHTTPRequest(sig, ip, asn, cs)
		return
	}

	// Track signal types (for dashboard visibility)
	switch sig.Type {
	case apiv1.SignalType_SIGNAL_SYN_FLOOD:
		metrics.SynFloods.Inc()
		metrics.TCPDetections.Inc()
		logrus.WithField("ip", ip.String()).Debug("Tracked SYN flood signal")
	case apiv1.SignalType_SIGNAL_ICMP_FLOOD:
		metrics.ICMPDetections.Inc()
		// Track highest ICMP rate (just set the weight value)
		if sig.Weight > 0 {
			metrics.HighestICMPRate.Set(sig.Weight)
			logrus.WithFields(logrus.Fields{"ip": ip.String(), "rate": sig.Weight}).Debug("Tracked ICMP flood signal")
		}
	case apiv1.SignalType_SIGNAL_UDP_FLOOD:
		metrics.UDPDetections.Inc()
		// Track highest UDP rate (just set the weight value)
		if sig.Weight > 0 {
			metrics.HighestUDPRate.Set(sig.Weight)
			logrus.WithFields(logrus.Fields{"ip": ip.String(), "rate": sig.Weight}).Debug("Tracked UDP flood signal")
		}
	case apiv1.SignalType_SIGNAL_BAD_FLAGS:
		metrics.FlagBlocks.Inc()
		metrics.TCPDetections.Inc()
		logrus.WithField("ip", ip.String()).Debug("Tracked bad flags signal")
	case apiv1.SignalType_SIGNAL_INCOMPLETE_HANDSHAKE:
		metrics.TCPDetections.Inc()
	}

	// Rate limiting check
	if a.checkRateLimit(ip, asn) {
		logrus.WithFields(logrus.Fields{
			"ip":  ip.String(),
			"asn": asn,
		}).Debug("Rate limit exceeded")

		if !a.Config.DryRun {
			a.ReputationHelper.PenalizeIP(ip, 10.0, "Rate limit exceeded")
			// Increment appropriate block metric based on signal type
			switch sig.Type {
			case apiv1.SignalType_SIGNAL_UDP_FLOOD:
				metrics.UDPBlocks.Inc()
			case apiv1.SignalType_SIGNAL_SYN_FLOOD, apiv1.SignalType_SIGNAL_BAD_FLAGS, apiv1.SignalType_SIGNAL_INCOMPLETE_HANDSHAKE:
				metrics.TCPBlocks.Inc()
			case apiv1.SignalType_SIGNAL_ICMP_FLOOD:
				metrics.ICMPBlocks.Inc()
			default:
				// For HTTP/SPOE signals, count as HAProxy blocks
				if sig.Type >= apiv1.SignalType_SIGNAL_BOT_UA {
					metrics.HAProxyBlocks.Inc()
				}
			}

			a.sendCommand(cs, &apiv1.Command{
				Type:   apiv1.CommandType_COMMAND_BLOCK_IP,
				Ip:     sig.Ip,
				Reason: "Rate limit exceeded",
			})
		}
		return
	}

	// Record baseline observation
	if a.Baseline != nil && asn != "" && asn != "Unknown" && sig.TcpContext != nil {
		obs := baseline.ObservationData{
			TTL:        uint8(sig.TcpContext.Ttl),
			WindowSize: uint16(sig.TcpContext.WindowSize),
			Timestamp:  time.Now(),
		}
		a.Baseline.RecordObservation(asn, obs)
	}

	// Record connection pattern
	if a.PatternTracker != nil && sig.TcpContext != nil {
		meta := patterns.ConnectionMetadata{
			TTL:        uint8(sig.TcpContext.Ttl),
			WindowSize: uint16(sig.TcpContext.WindowSize),
			MSS:        uint16(sig.TcpContext.Mss),
			ASN:        asn,
		}
		a.PatternTracker.RecordConnection(ip, meta)
	}

	// Process TCP timestamp for clock skew analysis
	if sig.TcpContext != nil && sig.TcpContext.TcpTimestamp > 0 && a.ClockSkew != nil {
		a.ClockSkew.ProcessTimestamp(ip, sig.TcpContext.TcpTimestamp)
	}

	// Process payload entropy
	if sig.TcpContext != nil && sig.TcpContext.EntropyScore > 0 && a.Entropy != nil {
		a.Entropy.ProcessEntropy(ip, uint8(sig.TcpContext.EntropyScore))
	}

	// Convert metadata from proto type
	metadata := make(map[string]interface{})
	for k, v := range sig.Metadata {
		metadata[k] = v
	}
	if sig.Ja4S != "" {
		metadata["ja4"] = sig.Ja4S
	}
	if sig.Ja4H != "" {
		metadata["ja4h"] = sig.Ja4H
	}
	if sig.Ja4T != "" {
		metadata["ja4t"] = sig.Ja4T
	}

	// Preserve HTTP context for ML training (session recordings)
	if sig.HttpContext != nil {
		metadata["path"] = sig.HttpContext.Path
		metadata["method"] = sig.HttpContext.Method
		metadata["user_agent"] = sig.HttpContext.UserAgent
		metadata["host"] = sig.HttpContext.Host
		metadata["referer"] = sig.HttpContext.Referer
		metadata["accept_language"] = sig.HttpContext.AcceptLanguage
		metadata["accept_encoding"] = sig.HttpContext.AcceptEncoding
		metadata["has_cookies"] = sig.HttpContext.HasCookies
		metadata["client_req_ms"] = sig.HttpContext.ClientReqMs
		metadata["packet_rtt_ms"] = sig.HttpContext.PacketRttMs
		metadata["dst_port"] = sig.HttpContext.DstPort
		metadata["dest_ip"] = sig.HttpContext.DstIp
		metadata["status_code"] = sig.HttpContext.StatusCode
	}

	// Preserve TCP context for ML training
	if sig.TcpContext != nil {
		metadata["ttl"] = sig.TcpContext.Ttl
		metadata["window_size"] = sig.TcpContext.WindowSize
		metadata["tcp_timestamp"] = sig.TcpContext.TcpTimestamp
		metadata["entropy_score"] = sig.TcpContext.EntropyScore
	}

	// Map type first
	sigType := mapProtoSignalType(sig.Type)

	// Map source
	source := aidetection.SourceTCP
	switch sig.Source {
	case apiv1.SignalSource_SOURCE_EBPF:
		source = aidetection.SourceTCP
	case apiv1.SignalSource_SOURCE_SPOE:
		source = aidetection.SourceSPOE
	case apiv1.SignalSource_SOURCE_FINGERPRINTER:
		source = aidetection.SourceFingerprint
	case apiv1.SignalSource_SOURCE_HAPROXY:
		source = aidetection.SourceSPOE
	case apiv1.SignalSource_SOURCE_ANALYZER:
		source = aidetection.SourceTCP
	}
	// Derive source for flood signals
	if source == aidetection.SourceTCP {
		switch sigType {
		case aidetection.SignalICMPFlood:
			source = aidetection.SourceICMP
		case aidetection.SignalUDPFlood:
			source = aidetection.SourceUDP
		}
	}

	// Emit signal to AI Engine for processing
	if a.AIEngine != nil {
		a.AIEngine.EmitSignal(aidetection.Signal{
			IP:        ip,
			Type:      sigType,
			Source:    source,
			Weight:    sig.Weight,
			Timestamp: time.Now(),
			ASN:       asn,
			JA4:       sig.Ja4S,
			JA4H:      sig.Ja4H,
			JA4T:      sig.Ja4T,
			Metadata:  metadata,
		})
	}

	score := 0.0
	if a.Reputation != nil {
		score = a.Reputation.GetScore(ip.String(), reputation.TypeIP)
	}

	if score > a.Config.ReputationThreshold {
		// Use ML model to validate blocking decision
		shouldBlock := true
		if a.MLModel != nil {
			features := a.extractMLFeatures(ip, asn, score)
			prediction := a.MLModel.Predict(features)

			// Only block if ML model agrees (high confidence)
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
				}).Info("ML model confirmed block decision")
			} else {
				logrus.WithFields(logrus.Fields{
					"ip":            ip.String(),
					"reputation":    score,
					"ml_confidence": prediction.Confidence,
				}).Warn("ML model rejected block - potential false positive")
			}
		}

		if shouldBlock && !a.Config.DryRun {
			// Increment appropriate block metric based on signal type
			switch sig.Type {
			case apiv1.SignalType_SIGNAL_UDP_FLOOD:
				metrics.UDPBlocks.Inc()
			case apiv1.SignalType_SIGNAL_SYN_FLOOD:
				metrics.TCPBlocks.Inc()
				metrics.SynFloods.Inc()
			case apiv1.SignalType_SIGNAL_BAD_FLAGS:
				metrics.TCPBlocks.Inc()
				metrics.FlagBlocks.Inc()
			case apiv1.SignalType_SIGNAL_INCOMPLETE_HANDSHAKE:
				metrics.TCPBlocks.Inc()
			case apiv1.SignalType_SIGNAL_ICMP_FLOOD:
				metrics.ICMPBlocks.Inc()
			default:
				// For HTTP/SPOE signals, count as HAProxy blocks
				if sig.Type >= apiv1.SignalType_SIGNAL_BOT_UA {
					metrics.HAProxyBlocks.Inc()
				}
			}

			a.sendCommand(cs, &apiv1.Command{
				Type:   apiv1.CommandType_COMMAND_BLOCK_IP,
				Ip:     sig.Ip,
				Reason: fmt.Sprintf("Reputation threshold exceeded: %.0f", score),
			})
		}
	}
}

func (a *Analyzer) sendCommand(cs *collectorStream, cmd *apiv1.Command) {
	if a.Config.DryRun {
		logrus.WithFields(logrus.Fields{"cmd": cmd.String()}).Debug("Dry run: not sending command")
		return
	}

	// Dedup block commands per IP for a short TTL
	if cmd.Type == apiv1.CommandType_COMMAND_BLOCK_IP && len(cmd.Ip) > 0 {
		ip := net.IP(cmd.Ip)
		if a.wasRecentlyBlocked(ip) {
			logrus.WithFields(logrus.Fields{"ip": ip.String()}).Debug("Block command skipped (recently blocked)")
			return
		}
		a.markBlocked(ip)
	}

	cs.sendMu.Lock()
	defer cs.sendMu.Unlock()

	if err := cs.stream.Send(cmd); err != nil {
		logrus.WithError(err).Debug("Failed to send command to collector")
	}
}

func (a *Analyzer) markBlocked(ip net.IP) {
	if ip == nil {
		return
	}
	const ttl = 60 * time.Second
	a.recentBlocksMu.Lock()
	defer a.recentBlocksMu.Unlock()
	a.recentBlocks[ip.String()] = time.Now()
	// Cleanup stale entries opportunistically
	for k, ts := range a.recentBlocks {
		if time.Since(ts) > ttl*2 {
			delete(a.recentBlocks, k)
		}
	}
}

func (a *Analyzer) wasRecentlyBlocked(ip net.IP) bool {
	if ip == nil {
		return false
	}
	const ttl = 60 * time.Second
	a.recentBlocksMu.Lock()
	defer a.recentBlocksMu.Unlock()
	if ts, ok := a.recentBlocks[ip.String()]; ok {
		return time.Since(ts) < ttl
	}
	return false
}

// Broadcast sends a command to all connected collectors
func (a *Analyzer) Broadcast(cmd *apiv1.Command) {
	if a.Config.DryRun {
		logrus.WithFields(logrus.Fields{"cmd": cmd.String()}).Debug("Dry run: not broadcasting command")
		return
	}
	a.collectorsMu.RLock()
	defer a.collectorsMu.RUnlock()

	for _, cs := range a.collectors {
		go a.sendCommand(cs, cmd)
	}
}

// LookupJA4H handles JA4H fingerprint lookups
func (a *Analyzer) LookupJA4H(ctx context.Context, req *apiv1.JA4HLookupRequest) (*apiv1.JA4HLookupResponse, error) {
	if a.JA4DB == nil {
		return &apiv1.JA4HLookupResponse{Found: false}, nil
	}

	fp := req.Fingerprint

	// 1. Try exact match from JA4 database first
	if a.JA4DB.IsKnownBot(fp) {
		info := a.JA4DB.GetInfo(fp)
		return &apiv1.JA4HLookupResponse{
			Found:           true,
			Application:     info,
			IsWildcardMatch: false,
		}, nil
	}

	// 2. For JA4H fingerprints, try partial matching on headers
	// JA4H format: "{protocol}_{header_hash}_{cookie_fields_hash}_{cookie_values_hash}"
	if strings.Count(fp, "_") == 3 {
		parts := strings.Split(fp, "_")
		headersPrefix := parts[0] + "_" + parts[1]

		// Search database for entries with matching headers
		if info, found := a.JA4DB.FindByHeadersPrefix(headersPrefix); found {
			return &apiv1.JA4HLookupResponse{
				Found:           true,
				Application:     info + " (probabilistic match - same headers)",
				IsWildcardMatch: true,
			}, nil
		}
	}

	return &apiv1.JA4HLookupResponse{Found: false}, nil
}

// VerifyBot handles bot verification requests
func (a *Analyzer) VerifyBot(ctx context.Context, req *apiv1.BotVerifyRequest) (*apiv1.BotVerifyResponse, error) {
	if a.BotVerifier == nil {
		return &apiv1.BotVerifyResponse{IsVerified: false}, nil
	}

	ip := net.IP(req.Ip)
	result := a.BotVerifier.Verify(ip, req.UserAgent)

	// Increment metric if verification succeeded
	if result.IsVerified {
		metrics.BotVerificationSuccess.WithLabelValues(string(result.BotType)).Inc()
	}

	// Only flag impersonation if the User-Agent matches a KNOWN bot pattern but verification fails
	// Don't flag unknown/generic clients as impersonators
	isImpersonation := !result.IsVerified && result.BotType != "" && result.BotType != "unknown"

	return &apiv1.BotVerifyResponse{
		IsVerified:      result.IsVerified,
		BotType:         string(result.BotType),
		IsImpersonation: isImpersonation,
	}, nil
}

// VerifyAICrawler handles AI crawler verification requests
func (a *Analyzer) VerifyAICrawler(ctx context.Context, req *apiv1.AICrawlerVerifyRequest) (*apiv1.AICrawlerVerifyResponse, error) {
	if a.AICrawlers == nil {
		return &apiv1.AICrawlerVerifyResponse{IsVerified: false}, nil
	}

	ip := net.IP(req.Ip)
	isVerified, crawlerType := a.AICrawlers.VerifyAICrawler(ip, req.UserAgent)

	// Increment metric if verification succeeded
	if isVerified {
		metrics.BotVerificationSuccess.WithLabelValues(string(crawlerType)).Inc()
	}

	// Check if it's an impersonation (matches UA but fails IP verification)
	_, matchesUA := a.AICrawlers.MatchUserAgent(req.UserAgent)
	isImpersonation := matchesUA && !isVerified

	return &apiv1.AICrawlerVerifyResponse{
		IsVerified:      isVerified,
		CrawlerType:     string(crawlerType),
		IsImpersonation: isImpersonation,
	}, nil
}

// GetThreatIntel handles threat intelligence requests
func (a *Analyzer) GetThreatIntel(ctx context.Context, req *apiv1.ThreatIntelRequest) (*apiv1.ThreatIntelResponse, error) {
	if a.ThreatIntel == nil {
		return &apiv1.ThreatIntelResponse{}, nil
	}

	ip := net.IP(req.Ip)

	// Optionally trigger enrichment
	if req.Enrich {
		a.ThreatIntel.EnrichIP(ip)
	}

	info := a.ThreatIntel.GetEnrichedInfo(ip)
	if info == nil {
		return &apiv1.ThreatIntelResponse{
			IsKnownScanner: a.ThreatIntel.IsKnownScanner(ip),
			ThreatScore:    a.ThreatIntel.GetThreatScore(ip),
		}, nil
	}

	return &apiv1.ThreatIntelResponse{
		IsKnownScanner: info.IsKnownScanner,
		ThreatScore:    info.ThreatScore,
		OpenPorts:      int32(info.OpenPorts),
		Tags:           info.Tags,
	}, nil
}

// GetReputation handles reputation lookup requests
func (a *Analyzer) GetReputation(ctx context.Context, req *apiv1.ReputationRequest) (*apiv1.ReputationResponse, error) {
	if a.Reputation == nil {
		return &apiv1.ReputationResponse{Score: 0}, nil
	}

	// Use EntityType from request (defaults to "ip")
	entityType := reputation.TypeIP
	if req.Type != "" {
		entityType = reputation.EntityType(req.Type)
	}

	score := a.Reputation.GetScore(req.Key, entityType)
	return &apiv1.ReputationResponse{Score: score}, nil
}

// Note: Metrics are exposed via Prometheus HTTP endpoint in the collector

// HandleDetection implements aidetection.DetectionHandler - sends BLOCK commands to collectors
func (a *Analyzer) HandleDetection(event aidetection.DetectionEvent) {
	threshold := a.Config.AIConfidenceThreshold
	if threshold == 0 {
		threshold = 0.7 // default if unset
	}
	scoreBlock := a.Config.AIBlockScoreThreshold
	if scoreBlock == 0 {
		scoreBlock = 15
	}
	metrics.AIConfidenceThreshold.Set(threshold)

	// Only block based on confidence (ML-driven) OR for DDoS with high score
	isDDoS := event.BotCategory == aidetection.BotCategoryDDoS

	// For non-DDoS: only confidence matters
	if !isDDoS && event.Confidence < threshold {
		metrics.AIDetectionsByAction.WithLabelValues("below_threshold").Inc()
		logrus.WithFields(logrus.Fields{
			"ip":         event.IP,
			"ja4h":       event.JA4H,
			"confidence": event.Confidence,
			"threshold":  threshold,
			"score":      event.Score,
		}).Debug("Detection below confidence threshold (non-DDoS), not blocking")
		return
	}

	// For DDoS: check confidence OR score
	if isDDoS && event.Score < scoreBlock && event.Confidence < threshold {
		metrics.AIDetectionsByAction.WithLabelValues("below_threshold").Inc()
		logrus.WithFields(logrus.Fields{
			"ip":         event.IP,
			"ja4h":       event.JA4H,
			"confidence": event.Confidence,
			"threshold":  threshold,
			"score":      event.Score,
		}).Debug("DDoS detection below both thresholds, not blocking")
		return
	}

	// Block by IP if available
	if event.IP != nil {
		ua := extractUserAgent(event.Signals)
		logFields := logrus.Fields{
			"component":     "analyzer",
			"event":         "block_command",
			"ip":            event.IP.String(),
			"asn":           event.ASN,
			"ja4":           event.JA4,
			"ja4h":          event.JA4H,
			"confidence":    event.Confidence,
			"threshold":     threshold,
			"ml_confidence": event.MLConfidence,
			"ml_category":   event.MLCategory,
			"bot_category":  event.BotCategory,
			"reason":        event.BlockReason,
			"user_agent":    ua,
			"duration_secs": 300,
		}

		// Allow legitimate/verified bots (observe only)
		isJA4Verified := false
		for _, sig := range event.Signals {
			if sig.Type == aidetection.SignalJA4HBotMatch {
				if sig.Metadata != nil {
					if v, ok := sig.Metadata["verified"].(bool); ok && v {
						isJA4Verified = true
						break
					}
				}
			}
		}
		if event.BotCategory == aidetection.BotCategoryLegitimate || isJA4Verified {
			metrics.AIDetectionsByAction.WithLabelValues("legit_allow").Inc()
			if metrics.IsHighCardinalityEnabled() {
				metrics.AIRecentDetections.WithLabelValues(
					event.IP.String(), event.ASN, event.Org, string(event.BotCategory), event.BlockReason, ua,
					fmt.Sprintf("%.3f", event.Confidence), fmt.Sprintf("%.2f", threshold), event.JA4H,
				).Set(float64(time.Now().Unix()))
			}
			logrus.WithFields(logFields).Info("Legitimate/verified bot detected, not blocking")
			return
		}

		// Dry run mode - log but don't block
		if a.Config.DryRun {
			logFields["dry_run"] = true
			metrics.AIDetectionsByAction.WithLabelValues("dry_run").Inc()
			if metrics.IsHighCardinalityEnabled() {
				metrics.AIRecentDetections.WithLabelValues(
					event.IP.String(), event.ASN, event.Org, string(event.BotCategory), event.BlockReason, ua,
					fmt.Sprintf("%.3f", event.Confidence), fmt.Sprintf("%.2f", threshold), event.JA4H,
				).Set(float64(time.Now().Unix()))
			}
			logrus.WithFields(logFields).Info("AI Detection triggered (DRY RUN - not blocking)")
			return
		}

		top := topSignals(event.SignalBreakdown, 3)
		for _, sig := range top {
			metrics.AIBlocksBySignal.WithLabelValues(string(sig)).Inc()
		}
		metrics.AIDetectionsByAction.WithLabelValues("block").Inc()
		if metrics.IsHighCardinalityEnabled() {
			metrics.AIRecentDetections.WithLabelValues(
				event.IP.String(), event.ASN, event.Org, string(event.BotCategory), event.BlockReason, ua,
				fmt.Sprintf("%.3f", event.Confidence), fmt.Sprintf("%.2f", threshold), event.JA4H,
			).Set(float64(time.Now().Unix()))
		}

		cmd := &apiv1.Command{
			Type:            apiv1.CommandType_COMMAND_BLOCK_IP,
			Ip:              event.IP,
			Reason:          event.BlockReason,
			Source:          "ai_detection",
			DurationSeconds: 300, // 5 minutes default
		}

		logrus.WithFields(logFields).Info("AI Detection triggered BLOCK command")
		a.Broadcast(cmd)
	}
}

func (a *Analyzer) runBaselineCalibrator() {
	defer a.wg.Done()
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			if a.Baseline != nil {
				// Log baseline stats periodically
				calibratedASNs, totalObs := a.Baseline.GetStats()
				logrus.WithFields(logrus.Fields{
					"calibrated_asns":    calibratedASNs,
					"total_observations": totalObs,
				}).Debug("Baseline calibrator stats")
			}
		}
	}
}

func (a *Analyzer) updateHTTPRate(ip net.IP, asn string) (float64, float64) {
	const tau = time.Second
	now := time.Now()

	update := func(m map[string]*ewma.State, key string) float64 {
		if m[key] == nil {
			m[key] = &ewma.State{Value: 1.0, LastTime: now}
			return 1.0
		}

		dt := now.Sub(m[key].LastTime)
		if dt <= 0 {
			return m[key].Value
		}

		value := 1.0 / dt.Seconds()
		newState := ewma.Update(*m[key], value, now, tau)
		m[key] = &newState
		return newState.Value
	}

	a.httpRateMu.Lock()
	defer a.httpRateMu.Unlock()

	ipRate := 0.0
	if ip != nil {
		ipRate = update(a.httpRateByIP, ip.String())
	}
	asnRate := 0.0
	if asn != "" && asn != "Unknown" {
		asnRate = update(a.httpRateByASN, asn)
	}
	return ipRate, asnRate
}

func (a *Analyzer) updateProxyLag(asn string, lag float64) float64 {
	const tau = 30 * time.Second
	if asn == "" || asn == "Unknown" {
		return 0
	}

	a.httpRateMu.Lock()
	defer a.httpRateMu.Unlock()

	now := time.Now()
	if a.proxyLagByASN[asn] == nil {
		a.proxyLagByASN[asn] = &ewma.State{Value: lag, LastTime: now}
		return lag
	}

	newState := ewma.Update(*a.proxyLagByASN[asn], lag, now, tau)
	a.proxyLagByASN[asn] = &newState
	return newState.Value
}

func (a *Analyzer) shouldEmitLatencyAnomaly(ip net.IP) bool {
	const ttl = 30 * time.Second
	if ip == nil {
		return true
	}
	key := ip.String()
	a.latencyMu.Lock()
	defer a.latencyMu.Unlock()
	now := time.Now()
	if prev, ok := a.latencyAnomalyThrottle[key]; ok {
		if now.Sub(prev) < ttl {
			return false
		}
	}
	a.latencyAnomalyThrottle[key] = now
	return true
}

func (a *Analyzer) updatePathEntropy(ip net.IP, path string) (float64, bool, bool, int, int) {
	const window = 5 * time.Minute
	const maxEvents = 200
	if ip == nil || path == "" {
		return 0, false, false, 0, 0
	}
	key := ip.String()
	a.pathMu.Lock()
	pw := a.pathWindows[key]
	now := time.Now()
	if pw == nil {
		pw = &pathWindow{Counts: make(map[string]int)}
		a.pathWindows[key] = pw
	}
	pw.Events = append(pw.Events, pathEvent{Path: path, Ts: now})
	pw.Counts[path]++
	pw.Total++
	// prune
	i := 0
	for i < len(pw.Events) {
		if now.Sub(pw.Events[i].Ts) <= window && len(pw.Events) <= maxEvents {
			break
		}
		old := pw.Events[i]
		pw.Counts[old.Path]--
		if pw.Counts[old.Path] <= 0 {
			delete(pw.Counts, old.Path)
		}
		pw.Total--
		i++
	}
	if i > 0 {
		pw.Events = pw.Events[i:]
	}
	// entropy
	entropy := 0.0
	if pw.Total > 0 {
		for _, c := range pw.Counts {
			p := float64(c) / float64(pw.Total)
			entropy -= p * math.Log2(p)
		}
	}
	unique := len(pw.Counts)

	// sequential numeric id detection
	seqNum := false
	ln := len(path)
	j := ln - 1
	for j >= 0 && path[j] >= '0' && path[j] <= '9' {
		j--
	}
	if j < ln-1 {
		nStr := path[j+1:]
		if n, err := strconv.ParseInt(nStr, 10, 64); err == nil {
			if pw.HasLastNumeric && pw.LastNumeric+1 == n {
				pw.SeqStreak++
			} else {
				pw.SeqStreak = 1
			}
			pw.LastNumeric = n
			pw.HasLastNumeric = true
			if pw.SeqStreak >= 5 {
				seqNum = true
			}
		}
	} else {
		pw.SeqStreak = 0
		pw.HasLastNumeric = false
	}

	// sequential alpha id detection (aa, ab, ac...)
	seqAlpha := false
	k := ln - 1
	for k >= 0 && ((path[k] >= 'a' && path[k] <= 'z') || (path[k] >= 'A' && path[k] <= 'Z')) {
		k--
	}
	if k < ln-1 {
		aStr := strings.ToLower(path[k+1:])
		if aVal := alphaToInt(aStr); aVal >= 0 {
			if pw.HasLastAlpha && pw.LastAlpha+1 == aVal {
				pw.AlphaSeqStreak++
			} else {
				pw.AlphaSeqStreak = 1
			}
			pw.LastAlpha = aVal
			pw.HasLastAlpha = true
			if pw.AlphaSeqStreak >= 5 {
				seqAlpha = true
			}
		}
	} else {
		pw.AlphaSeqStreak = 0
		pw.HasLastAlpha = false
	}

	a.pathMu.Unlock()
	return entropy, seqNum, seqAlpha, unique, pw.Total
}

// trackHTTPErrors tracks 404 and 403 errors to detect scanners and vulnerability probers
// Returns (total404, total403, consecutive4xx) for the IP in the window
func (a *Analyzer) trackHTTPErrors(ip net.IP, statusCode uint32, path string) (int, int, int) {
	const window = 3 * time.Minute
	const maxEvents = 100

	if ip == nil || statusCode == 0 {
		return 0, 0, 0
	}

	key := ip.String()
	a.httpErrorMu.Lock()
	defer a.httpErrorMu.Unlock()

	w := a.httpErrorWindows[key]
	now := time.Now()

	if w == nil {
		w = &httpErrorWindow{}
		a.httpErrorWindows[key] = w
	}

	// Add new event
	w.Events = append(w.Events, httpErrorEvent{
		StatusCode: statusCode,
		Path:       path,
		Ts:         now,
	})
	w.Total++

	// Track specific error types
	if statusCode == 404 {
		w.NotFound404++
	} else if statusCode == 403 {
		w.Forbidden403++
	}

	// Track consecutive 4xx errors
	if statusCode >= 400 && statusCode < 500 {
		if w.LastStatus >= 400 && w.LastStatus < 500 {
			w.ConsecutiveError++
		} else {
			w.ConsecutiveError = 1
		}
	} else {
		w.ConsecutiveError = 0
	}
	w.LastStatus = statusCode

	// Prune old events
	i := 0
	for i < len(w.Events) {
		if now.Sub(w.Events[i].Ts) <= window && len(w.Events) <= maxEvents {
			break
		}
		old := w.Events[i]
		w.Total--
		if old.StatusCode == 404 {
			w.NotFound404--
		} else if old.StatusCode == 403 {
			w.Forbidden403--
		}
		i++
	}
	if i > 0 {
		w.Events = w.Events[i:]
	}

	return w.NotFound404, w.Forbidden403, w.ConsecutiveError
}

func alphaToInt(s string) int64 {
	var v int64
	if s == "" {
		return -1
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 'a' || c > 'z' {
			return -1
		}
		v = v*26 + int64(c-'a')
	}
	return v
}

// cleanupTrackingMaps removes stale entries from path and HTTP error tracking maps
func (a *Analyzer) cleanupTrackingMaps() {
	now := time.Now()
	cutoff := now.Add(-15 * time.Minute) // Clean up entries older than 15 minutes

	// Clean path windows
	a.pathMu.Lock()
	for ip, pw := range a.pathWindows {
		// Remove if no recent activity
		if len(pw.Events) == 0 || (len(pw.Events) > 0 && pw.Events[len(pw.Events)-1].Ts.Before(cutoff)) {
			delete(a.pathWindows, ip)
		}
	}
	pathCount := len(a.pathWindows)
	a.pathMu.Unlock()

	// Clean HTTP error windows
	a.httpErrorMu.Lock()
	for ip, w := range a.httpErrorWindows {
		// Remove if no recent activity
		if len(w.Events) == 0 || (len(w.Events) > 0 && w.Events[len(w.Events)-1].Ts.Before(cutoff)) {
			delete(a.httpErrorWindows, ip)
		}
	}
	errorCount := len(a.httpErrorWindows)
	a.httpErrorMu.Unlock()

	// Clean HTTP rate tracking
	a.httpRateMu.Lock()
	for ip, state := range a.httpRateByIP {
		if state != nil && time.Since(state.LastTime) > 15*time.Minute {
			delete(a.httpRateByIP, ip)
		}
	}
	for asn, state := range a.httpRateByASN {
		if state != nil && time.Since(state.LastTime) > 15*time.Minute {
			delete(a.httpRateByASN, asn)
		}
	}
	httpRateIPCount := len(a.httpRateByIP)
	httpRateASNCount := len(a.httpRateByASN)
	a.httpRateMu.Unlock()

	// Clean rate limiters
	a.rateLimitersMu.Lock()
	for ip := range a.ipRateLimiters {
		// Keep limiters that are active; this is just a bounds check
		if len(a.ipRateLimiters) > 10000 {
			delete(a.ipRateLimiters, ip)
			break
		}
	}
	for asn := range a.asnRateLimiters {
		if len(a.asnRateLimiters) > 1000 {
			delete(a.asnRateLimiters, asn)
			break
		}
	}
	rateLimiterIPCount := len(a.ipRateLimiters)
	rateLimiterASNCount := len(a.asnRateLimiters)
	a.rateLimitersMu.Unlock()

	// Clean latency anomaly throttle
	a.latencyMu.Lock()
	for ip, t := range a.latencyAnomalyThrottle {
		if now.Sub(t) > 15*time.Minute {
			delete(a.latencyAnomalyThrottle, ip)
		}
	}
	latencyThrottleCount := len(a.latencyAnomalyThrottle)
	a.latencyMu.Unlock()

	// Clean recent blocks
	a.recentBlocksMu.Lock()
	for ip, t := range a.recentBlocks {
		if now.Sub(t) > 15*time.Minute {
			delete(a.recentBlocks, ip)
		}
	}
	recentBlocksCount := len(a.recentBlocks)
	a.recentBlocksMu.Unlock()

	logrus.WithFields(logrus.Fields{
		"path_windows":      pathCount,
		"error_windows":     errorCount,
		"http_rate_ips":     httpRateIPCount,
		"http_rate_asns":    httpRateASNCount,
		"rate_limiter_ips":  rateLimiterIPCount,
		"rate_limiter_asns": rateLimiterASNCount,
		"latency_throttles": latencyThrottleCount,
		"recent_blocks":     recentBlocksCount,
	}).Info("Cleaned up tracking maps")
}

func (a *Analyzer) Close() {
	a.cancel()

	if a.Reputation != nil {
		a.Reputation.Stop()
	}

	// Stop model watcher
	if a.ModelWatcher != nil {
		logrus.Info("Stopping model watcher...")
		a.ModelWatcher.Stop()
	}

	// Shutdown gRPC server with timeout
	if a.grpcServer != nil {
		stopped := make(chan struct{})
		go func() {
			a.grpcServer.GracefulStop()
			close(stopped)
		}()

		select {
		case <-stopped:
			logrus.Info("gRPC server stopped gracefully")
		case <-time.After(5 * time.Second):
			logrus.Warn("gRPC server graceful stop timeout, forcing stop")
			a.grpcServer.Stop()
		}
	}

	// Shutdown metrics server
	if a.metricsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := a.metricsServer.Shutdown(ctx); err != nil {
			logrus.WithError(err).Warn("Metrics server shutdown error")
		}
	}

	if a.listener != nil {
		a.listener.Close()
	}
	if a.GeoIP != nil {
		a.GeoIP.Close()
	}

	// Wait for goroutines with timeout
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logrus.Info("Analyzer stopped gracefully")
	case <-time.After(10 * time.Second):
		logrus.Warn("Shutdown timeout waiting for goroutines")
	}
}

func startPprof(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	logrus.WithField("addr", addr).Info("pprof server listening")
	if err := http.ListenAndServe(addr, mux); err != nil {
		logrus.WithError(err).Warn("pprof server exited")
	}
}
