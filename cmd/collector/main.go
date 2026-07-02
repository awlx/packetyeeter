package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"PacketYeeter/pkg/collector"
)

func main() {
	var (
		iface           = flag.String("i", "eth0", "Network interface to attach to")
		analyzerAddr    = flag.String("analyzer-addr", "127.0.0.1:9090", "Analyzer gRPC address")
		metricsAddr     = flag.String("metrics-addr", ":2112", "Prometheus metrics HTTP listen address")
		haproxyPort     = flag.Int("haproxy-port", 8765, "HAProxy peer protocol port")
		spoePort        = flag.Int("spoe-port", 9876, "SPOE agent port")
		socketPath      = flag.String("socket", "/var/run/packetyeeter-collector.sock", "Unix socket for CLI")
		geoIPASNPath    = flag.String("geoip-asn", "", "Path to GeoLite2-ASN.mmdb")
		allowlist       = flag.String("allowlist", "", "Comma-separated CIDRs to allowlist (e.g., 10.0.0.0/8,192.168.1.0/24)")
		blockDuration   = flag.Duration("block-duration", 5*time.Minute, "Default block duration")
		pollInterval    = flag.Duration("poll-interval", 1*time.Second, "How often to poll eBPF maps")
		signalQueueSize = flag.Int("signal-queue-size", 10000, "Collector signal queue size")
		verbose         = flag.Bool("v", false, "Verbose logging")
	)
	flag.Parse()

	logger := logrus.New()
	if *verbose {
		logger.SetLevel(logrus.DebugLevel)
	}
	logger.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})

	cfg := collector.Config{
		Interface:       *iface,
		AnalyzerAddr:    *analyzerAddr,
		MetricsAddr:     *metricsAddr,
		SPOEAddr:        fmt.Sprintf(":%d", *spoePort),
		HAProxyPort:     *haproxyPort,
		SocketPath:      *socketPath,
		GeoIPASNPath:    *geoIPASNPath,
		AllowlistCIDRs:  *allowlist,
		BlockDuration:   *blockDuration,
		PollInterval:    *pollInterval,
		SignalQueueSize: *signalQueueSize,
	}

	coll, err := collector.New(cfg, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create collector")
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := coll.Start(ctx); err != nil {
		logger.WithError(err).Fatal("Failed to start collector")
	}

	logger.Info("PacketYeeter Collector started - relaying to analyzer at ", *analyzerAddr)

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down collector...")
	cancel()

	// Stop with timeout - SPOE library doesn't gracefully handle active connections
	done := make(chan struct{})
	go func() {
		coll.Stop()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("Collector stopped gracefully")
	case <-time.After(5 * time.Second):
		logger.Warn("Shutdown timeout - forcing exit")
	}
}
