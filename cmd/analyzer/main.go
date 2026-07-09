package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"PacketYeeter/pkg/analyzer"
	"PacketYeeter/pkg/buildinfo"
)

func main() {
	var (
		listenAddr       = flag.String("listen-addr", "0.0.0.0:9090", "gRPC listen address")
		metricsAddr      = flag.String("metrics-addr", ":9091", "Prometheus metrics HTTP listen address")
		inspectAddr      = flag.String("inspect-addr", "127.0.0.1:9092", "Inspector HTTP listen address")
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
		mlModelPath      = flag.String("ml-model", "", "Path to ONNX ML model file (optional, enables ML-based confidence adjustment)")
		dryRun           = flag.Bool("dry-run", false, "Monitor mode - log detections but don't send BLOCK commands")
		showVersion      = flag.Bool("version", false, "Print build version and exit")
		verbose          = flag.Bool("v", false, "Verbose logging")
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

	cfg := analyzer.Config{
		ListenAddr:                   *listenAddr,
		MetricsAddr:                  *metricsAddr,
		InspectorAddr:                *inspectAddr,
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
		DryRun:                       *dryRun,
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
