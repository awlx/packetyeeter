package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"PacketYeeter/pkg/analyzer"
	"PacketYeeter/pkg/analyzer/sustained"
	"PacketYeeter/pkg/buildinfo"
)

func main() {
	var (
		listenAddr       = flag.String("listen-addr", "0.0.0.0:9090", "gRPC listen address")
		metricsAddr      = flag.String("metrics-addr", ":9091", "Prometheus metrics HTTP listen address")
		inspectAddr      = flag.String("inspect-addr", "127.0.0.1:9092", "Inspector HTTP listen address")
		inspectTrusted   = flag.String("inspect-trusted-hosts", "", "Comma-separated extra Host/Origin hostnames the inspector trusts for state-mutating requests, in addition to loopback (e.g. a reverse-proxy hostname)")
		geoIPASNPath     = flag.String("geoip-asn", "", "Path to GeoLite2-ASN.mmdb")
		geoIPCountryPath = flag.String("geoip-country", "", "Path to GeoLite2-Country.mmdb or GeoLite2-City.mmdb (optional, enables country enrichment)")
		repThreshold     = flag.Float64("reputation-threshold", 75.0, "Reputation threshold for blocking")
		repMaxEntries    = flag.Int("reputation-max-entries", 500000, "Maximum reputation entries to keep")
		repMaxAge        = flag.Duration("reputation-max-age", 24*time.Hour, "Maximum age to retain reputation entries")
		repASNMaxHosts   = flag.Int("reputation-asn-max-hosts", 5000, "Maximum distinct hosts tracked per ASN")
		aiThreshold      = flag.Float64("ai-confidence-threshold", 0.7, "AI detection confidence threshold for blocking (0-1)")
		highCard         = flag.Bool("enable-high-cardinality-metrics", false, "Enable per-IP/JA4 high-cardinality metrics (may explode series)")
		enablePprof      = flag.Bool("enable-pprof", false, "Enable pprof profiling server")
		pprofAddr        = flag.String("pprof-addr", ":6060", "pprof listen address")
		ddosMinInc       = flag.Int("ddos-min-incomplete", 400, "DDoS: min incomplete handshakes per IP per 10s")
		ddosMinPattern   = flag.Int("ddos-min-pattern", 800, "DDoS: min pattern signals (highfreq+conn+timing) per IP per 10s")
		ddosMinTotal     = flag.Int("ddos-min-total", 1500, "DDoS: min total signals per IP per 10s")
		ddosRequireHF    = flag.Bool("ddos-require-highfreq", true, "DDoS: require high-frequency or flood signals present")
		disableDDoS      = flag.Bool("disable-ddos-category", false, "Disable DDoS category labeling (still detects other bots)")
		aiWorkers        = flag.Int("ai-workers", 16, "AI engine worker count")
		aiQueueSize      = flag.Int("ai-queue-size", 10000, "AI engine signal queue size")
		maxCollectors    = flag.Int("max-collectors", 1024, "Maximum concurrent collector streams (bounds fan-out/goroutines on the unauthenticated signal plane)")
		mlModelPath      = flag.String("ml-model", "", "Path to ONNX ML model file (optional, enables ML-based confidence adjustment)")
		dryRun           = flag.Bool("dry-run", false, "Monitor mode - log detections but don't send BLOCK commands")

		sustainedDefaults = sustained.DefaultConfig()

		sustainedEnabled   = flag.Bool("sustained-enabled", false, "Enable sustained-download detection (volume and breadth over a sliding window)")
		sustainedEnforce   = flag.Bool("sustained-enforce", false, "Block sustained-download detections instead of only reporting them")
		sustainedWindow    = flag.Int("sustained-window-seconds", sustainedDefaults.WindowSeconds, "Sustained-download sliding window length in seconds")
		sustainedEvalEvery = flag.Int("sustained-evaluation-interval-seconds", sustainedDefaults.EvaluationIntervalSeconds, "How often sustained-download clients are evaluated")
		sustainedPublish   = flag.Int("sustained-publish-interval-seconds", sustainedDefaults.PublishIntervalSeconds, "Minimum gap between sustained-download decisions for the same client")
		sustainedMinReq    = flag.Uint64("sustained-min-requests", sustainedDefaults.MinimumRequests, "Sustained-download: minimum requests in the window")
		sustainedMinBytes  = flag.Uint64("sustained-min-bytes", sustainedDefaults.MinimumBytes, "Sustained-download: minimum egress bytes in the window (volume path only)")
		sustainedMinRes    = flag.Int("sustained-min-resources", sustainedDefaults.MinimumResources, "Sustained-download: minimum distinct resources in the window")
		sustainedMinSect   = flag.Int("sustained-min-sections", sustainedDefaults.MinimumSections, "Sustained-download: minimum distinct sections in the window")
		sustainedMaxRatio  = flag.Int("sustained-max-resources-per-section-percent", sustainedDefaults.MaximumResourcesPerSectionPercent, "Sustained-download: resources-per-section ceiling for the shape path, as a percentage")
		sustainedMaxClient = flag.Int("sustained-max-clients", sustainedDefaults.MaximumClients, "Sustained-download: maximum clients tracked concurrently")
		sustainedMaxRes    = flag.Int("sustained-max-resources-per-client", sustainedDefaults.MaximumResourcesPerClient, "Sustained-download: maximum distinct resources retained per client (0 uses the resource minimum)")
		sustainedHold      = flag.Int("sustained-hold-seconds", sustainedDefaults.HoldSeconds, "Sustained-download: how long a selected client stays selected after it stops clearing thresholds (negative disables the hold)")
		sustainedMaxHold   = flag.Int("sustained-max-hold-seconds", sustainedDefaults.MaximumHoldSeconds, "Sustained-download: hard ceiling on the enforcement hold")
		sustainedRelease   = flag.Int("sustained-release-factor-percent", sustainedDefaults.ReleaseFactorPercent, "Sustained-download: percentage of the thresholds a held client must stay above to remain held")
		sustainedRepFactor = flag.Int64("sustained-reputation-factor", sustainedDefaults.ReputationFactor, "Sustained-download: threshold multiplier applied to verified good-reputation clients")

		showVersion = flag.Bool("version", false, "Print build version and exit")
		verbose     = flag.Bool("v", false, "Verbose logging")
	)
	flag.Parse()
	if *showVersion {
		fmt.Println(buildinfo.String())
		return
	}

	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}
	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})

	var inspectorTrustedHosts []string
	for _, h := range strings.Split(*inspectTrusted, ",") {
		if h = strings.TrimSpace(h); h != "" {
			inspectorTrustedHosts = append(inspectorTrustedHosts, h)
		}
	}

	cfg := analyzer.Config{
		ListenAddr:                   *listenAddr,
		MetricsAddr:                  *metricsAddr,
		InspectorAddr:                *inspectAddr,
		InspectorTrustedHosts:        inspectorTrustedHosts,
		GeoIPASNPath:                 *geoIPASNPath,
		GeoIPCountryPath:             *geoIPCountryPath,
		ReputationThreshold:          *repThreshold,
		ReputationMaxEntries:         *repMaxEntries,
		ReputationMaxAge:             *repMaxAge,
		ReputationASNMaxHosts:        *repASNMaxHosts,
		AIConfidenceThreshold:        *aiThreshold,
		EnableHighCardinalityMetrics: *highCard,
		EnablePprof:                  *enablePprof,
		PprofAddr:                    *pprofAddr,
		DDoSIncompleteThreshold:      *ddosMinInc,
		DDoSPatternThreshold:         *ddosMinPattern,
		DDoSTotalThreshold:           *ddosMinTotal,
		DDoSRequireHighFreq:          *ddosRequireHF,
		DisableDDoSCategory:          *disableDDoS,
		AIWorkers:                    *aiWorkers,
		AIQueueSize:                  *aiQueueSize,
		MLModelPath:                  *mlModelPath,
		MaxCollectors:                *maxCollectors,
		DryRun:                       *dryRun,
		Sustained: sustained.Config{
			Enabled:                           *sustainedEnabled,
			Enforce:                           *sustainedEnforce,
			WindowSeconds:                     *sustainedWindow,
			EvaluationIntervalSeconds:         *sustainedEvalEvery,
			PublishIntervalSeconds:            *sustainedPublish,
			MinimumRequests:                   *sustainedMinReq,
			MinimumBytes:                      *sustainedMinBytes,
			MinimumResources:                  *sustainedMinRes,
			MinimumSections:                   *sustainedMinSect,
			MaximumResourcesPerSectionPercent: *sustainedMaxRatio,
			MaximumClients:                    *sustainedMaxClient,
			MaximumResourcesPerClient:         *sustainedMaxRes,
			HoldSeconds:                       *sustainedHold,
			MaximumHoldSeconds:                *sustainedMaxHold,
			ReleaseFactorPercent:              *sustainedRelease,
			ReputationFactor:                  *sustainedRepFactor,
		},
	}

	a, err := analyzer.New(cfg)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create analyzer")
	}

	if err := a.Start(); err != nil {
		logrus.WithError(err).Fatal("Failed to start analyzer")
	}

	logFields := logrus.Fields{"addr": *listenAddr}
	if *dryRun {
		logFields["dry_run"] = true
		logrus.WithFields(logFields).Warn("PacketYeeter Analyzer started in DRY RUN mode - detections will be logged but not blocked")
	} else {
		logrus.WithFields(logFields).Info("PacketYeeter Analyzer started")
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logrus.Info("Shutting down analyzer...")
	a.Close()
}
