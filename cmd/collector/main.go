package main

import (
	"context"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"PacketYeeter/pkg/buildinfo"
	"PacketYeeter/pkg/collector"
	"PacketYeeter/pkg/collector/ebpf"
	"PacketYeeter/pkg/grpctls"
)

func main() {
	var (
		iface           = flag.String("i", "eth0", "Network interface to attach to (the outside port in scrub mode)")
		mode            = flag.String("mode", "host", "host: protect this host; scrub: forward clean traffic from -i to -inside-if")
		insideIf        = flag.String("inside-if", "", "Scrub mode: inside port that clean traffic is forwarded to")
		xdpMode         = flag.String("xdp-mode", "auto", "XDP attach mode: auto, native or generic")
		allowGeneric    = flag.Bool("allow-generic", false, "Scrub mode: allow generic XDP (labs only, far slower)")
		readyzDrain     = flag.Duration("readyz-drain", collector.DefaultReadyzDrain, "Scrub mode: how long /readyz reports not ready on shutdown before detaching")
		readyzAnalyzer  = flag.Duration("readyz-analyzer-grace", collector.DefaultReadyzAnalyzerGrace, "Scrub mode: >0 makes /readyz require the analyzer stream, staying ready this long after it breaks; 0 = analyzer only reported as degraded")
		hsTimeout       = flag.Duration("handshake-timeout", collector.DefaultHandshakeTimeout, "How long a SYN may go without the client's ACK before it is reported as an incomplete handshake")
		slowPathPPS     = flag.Uint("scrub-slow-path-pps", collector.DefaultScrubSlowPathPPS, "Scrub mode: max packets/s handed to the kernel slow path across all CPUs, excess dropped (0 = unlimited)")
		fpInterval      = flag.Duration("fingerprint-interval", collector.DefaultFingerprintInterval, "Scrub mode: how often per-destination traffic fingerprints are sent to the analyzer (0 = off)")
		fpTop           = flag.Int("fingerprint-top", collector.DefaultFingerprintTop, "Scrub mode: fingerprint buckets sent per destination and interval, busiest first")
		synCookies      = flag.String("scrub-syn-cookies", "off", "Scrub mode: answer SYNs from unverified sources with a SYN cookie instead of forwarding them: off, auto (only destinations over -scrub-syn-cookie-syn-pps) or on. Linux 6.0+")
		synCookieStyle  = flag.String("scrub-syn-cookie-style", "oos", "Scrub mode: oos (out-of-sequence SYN-ACK; the client's RST verifies it and its SYN retry passes) or reset (valid SYN-ACK; the client's ACK verifies it and the node resets that connection)")
		synCookiePPS    = flag.Uint("scrub-syn-cookie-syn-pps", collector.DefaultSynCookieSynPPS, "Scrub mode: SYNs per second to one destination, across all CPUs, that start challenges in -scrub-syn-cookies auto (held for 30s)")
		synCookieTTL    = flag.Duration("scrub-syn-cookie-ttl", collector.DefaultSynCookieTTL, "Scrub mode: how long a source that answered a challenge stays verified")
		analyzerAddr    = flag.String("analyzer-addr", "127.0.0.1:9090", "Analyzer gRPC address")
		analyzerTLSCA   = flag.String("analyzer-tls-ca", "", "PEM CA bundle that verifies the analyzer's certificate; enables TLS. Re-read on change")
		analyzerTLSCert = flag.String("analyzer-tls-cert", "", "PEM client certificate for mTLS to the analyzer (requires -analyzer-tls-key and -analyzer-tls-ca). Re-read on change")
		analyzerTLSKey  = flag.String("analyzer-tls-key", "", "PEM private key for -analyzer-tls-cert. Re-read on change")
		analyzerTLSName = flag.String("analyzer-tls-server-name", "", "Name to verify in the analyzer's certificate (default: host part of -analyzer-addr)")
		metricsAddr     = flag.String("metrics-addr", ":2112", "Prometheus metrics HTTP listen address")
		spoePort        = flag.Int("spoe-port", 9876, "SPOE agent port")
		socketPath      = flag.String("socket", "/var/run/packetyeeter-collector.sock", "Unix socket for CLI")
		geoIPASNPath    = flag.String("geoip-asn", "", "Path to GeoLite2-ASN.mmdb")
		allowlist       = flag.String("allowlist", "", "Comma-separated CIDRs to allowlist (e.g., 10.0.0.0/8,192.168.1.0/24)")
		policy          = flag.String("policy", "", "Comma-separated per-CIDR policy overrides as CIDR=action (action = block|monitor), e.g. 203.0.113.0/24=block,198.51.100.0/24=monitor")
		blockDuration   = flag.Duration("block-duration", 5*time.Minute, "Default block duration")
		pollInterval    = flag.Duration("poll-interval", 1*time.Second, "How often to poll eBPF maps")
		signalQueueSize = flag.Int("signal-queue-size", 10000, "Collector signal queue size")
		dryRun          = flag.Bool("dry-run", false, "Monitor mode: log/count the collector's own kernel-space detections (bad flags, SYN flood, ICMP/UDP rate limits) without dropping traffic")
		egressAccount   = flag.Bool("egress-accounting", false, "Count bytes transmitted to each client on the TC egress path and report them to the analyzer (feeds sustained-download detection)")
		egressMinBytes  = flag.Uint64("egress-min-bytes", 1<<20, "Smallest per-poll egress byte delta that produces a signal")
		udpFragMode     = flag.String("udp-frag-mode", "rate", "Fragmented UDP / IPv6 fragment policy: rate (default, rate-limit only) or drop (legacy hard-drop)")
		showVersion     = flag.Bool("version", false, "Print build version and exit")
		verbose         = flag.Bool("v", false, "Verbose logging")
	)
	flag.Parse()
	if *showVersion {
		fmt.Println(buildinfo.String())
		return
	}

	logger := logrus.New()
	if *verbose {
		logger.SetLevel(logrus.DebugLevel)
	}
	logger.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})

	fragMode, err := ebpf.ParseUDPFragMode(*udpFragMode)
	if err != nil {
		logrus.WithError(err).Fatal("Invalid -udp-frag-mode")
	}
	collectorMode, err := ebpf.ParseMode(*mode)
	if err != nil {
		logrus.WithError(err).Fatal("Invalid -mode")
	}
	attachMode, err := ebpf.ParseXDPMode(*xdpMode)
	if err != nil {
		logrus.WithError(err).Fatal("Invalid -xdp-mode")
	}
	synCookieMode, err := ebpf.ParseSynCookieMode(*synCookies)
	if err != nil {
		logrus.WithError(err).Fatal("Invalid -scrub-syn-cookies")
	}
	cookieStyle, err := ebpf.ParseSynCookieStyle(*synCookieStyle)
	if err != nil {
		logrus.WithError(err).Fatal("Invalid -scrub-syn-cookie-style")
	}

	cfg := collector.Config{
		Interface:    *iface,
		AnalyzerAddr: *analyzerAddr,
		AnalyzerTLS: grpctls.ClientConfig{
			CAFile:     *analyzerTLSCA,
			CertFile:   *analyzerTLSCert,
			KeyFile:    *analyzerTLSKey,
			ServerName: *analyzerTLSName,
		},
		MetricsAddr:     *metricsAddr,
		SPOEAddr:        fmt.Sprintf(":%d", *spoePort),
		SocketPath:      *socketPath,
		GeoIPASNPath:    *geoIPASNPath,
		AllowlistCIDRs:  *allowlist,
		PolicyRules:     *policy,
		BlockDuration:   *blockDuration,
		PollInterval:    *pollInterval,
		SignalQueueSize: *signalQueueSize,
		DryRun:          *dryRun,

		EgressAccounting: *egressAccount,
		EgressMinBytes:   *egressMinBytes,
		UDPFragMode:      fragMode,

		Mode:            collectorMode,
		InsideInterface: *insideIf,
		XDPMode:         attachMode,
		AllowGeneric:    *allowGeneric,
		ReadyzDrain:     *readyzDrain,

		ReadyzAnalyzerGrace: *readyzAnalyzer,

		HandshakeTimeout: *hsTimeout,

		ScrubSlowPathPPS: uint32(min(*slowPathPPS, math.MaxUint32)),

		FingerprintInterval: *fpInterval,
		FingerprintTop:      *fpTop,

		SynCookies:      synCookieMode,
		SynCookieStyle:  cookieStyle,
		SynCookieSynPPS: uint32(min(*synCookiePPS, math.MaxUint32)),
		SynCookieTTL:    *synCookieTTL,
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
	// Do not cancel ctx here: in scrub mode Stop keeps the control plane
	// (analyzer commands, block GC, local_addrs sync) running during the
	// -readyz-drain period, and cancels it itself afterwards.

	// Stop with timeout - SPOE library doesn't gracefully handle active connections
	stopTimeout := 5 * time.Second
	if collectorMode == ebpf.ModeScrub {
		stopTimeout += *readyzDrain
	}
	done := make(chan struct{})
	go func() {
		coll.Stop()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("Collector stopped gracefully")
	case <-time.After(stopTimeout):
		logger.Warn("Shutdown timeout - forcing exit")
	}
}
