package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/collector/ebpf"
	"PacketYeeter/pkg/collector/haproxy/spoe"
	"PacketYeeter/pkg/geoip"
	"PacketYeeter/pkg/metrics"

	"github.com/cilium/ebpf/perf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Config holds collector configuration
type Config struct {
	Interface       string
	AnalyzerAddr    string
	MetricsAddr     string
	SPOEAddr        string // e.g., ":9876"
	SocketPath      string
	GeoIPASNPath    string
	AllowlistCIDRs  string // Comma-separated CIDRs
	PolicyRules     string // Comma-separated CIDR=action rules (action = block|monitor)
	BlockDuration   time.Duration
	PollInterval    time.Duration // How often to poll eBPF maps and send to analyzer
	SignalQueueSize int           // Collector signal queue size (default 10000)
	DryRun          bool          // If true, the collector's own kernel-space detections (bad flags, SYN flood, ICMP/UDP rate limits) log/count but never drop traffic

	// EgressAccounting enables the eBPF TC egress per-client byte counters that
	// feed the analyzer's sustained-download detection. Off by default: it adds
	// a map lookup and an atomic add per egress packet, and the detection it
	// feeds is only meaningful for workloads that serve bulk downloads.
	EgressAccounting bool
	// EgressMinBytes is the smallest per-poll byte delta that produces a
	// signal. It exists to keep ordinary browsing traffic off the signal
	// queue; sustained transfers clear it easily.
	EgressMinBytes uint64

	// UDPFragMode controls fragmented UDP / IPv6 fragment handling in XDP.
	// Use ebpf.UDPFragModeRate (default) or ebpf.UDPFragModeDrop.
	UDPFragMode uint32
}

// Collector is a thin relay layer that:
// 1. Loads eBPF programs and exposes maps
// 2. Streams raw events to the analyzer
// 3. Handles SPOE requests by forwarding to analyzer
// 4. Executes block/unblock commands from analyzer
type prevRate struct {
	lastTime uint64
	count    uint64
}

type Collector struct {
	Config Config

	// Components
	Loader *ebpf.Loader
	Maps   *ebpf.Maps
	GeoIP  *geoip.Provider
	Logger *logrus.Logger
	// allowedNetsMu guards allowedNets: executeCommand mutates it on the
	// command-stream goroutine while checkAllowlist reads it from the map
	// polling, perf-event, and SPOE goroutines.
	allowedNetsMu  sync.RWMutex
	allowedNets    []*net.IPNet
	policyRules    []ebpf.PolicyRule
	perfReader     *perf.Reader
	incidentReader *perf.Reader

	// gRPC connection to analyzer
	analyzerConn   *grpc.ClientConn
	analyzerClient apiv1.AnalyzerServiceClient
	signalStream   apiv1.AnalyzerService_StreamSignalsClient
	connected      atomic.Bool
	reconnectCh    chan struct{}

	// Signal queue (ring buffer)
	signalQueue chan *apiv1.Signal

	dropLogMu    sync.Mutex
	dropLogLast  time.Time
	dropLogCount int

	// Previous rates to compute pps across windows (monotonic timestamps)
	prevICMPRates   map[uint32]prevRate
	prevUDPRates    map[uint32]prevRate
	prevICMPRatesV6 map[[16]byte]prevRate
	prevUDPRatesV6  map[[16]byte]prevRate

	// Last-alerted timestamps for bad TCP flag scans, so repeated polls
	// don't re-emit a signal for the same kernel-observed event.
	prevBadFlagsSeen   map[uint32]uint64
	prevBadFlagsSeenV6 map[[16]byte]uint64

	// Last cumulative egress byte counters, so each poll reports only what the
	// client moved during that poll rather than the counter's whole history.
	prevEgressBytes   map[uint32]prevEgress
	prevEgressBytesV6 map[[16]byte]prevEgress

	// SYN timestamp cache for eBPF <-> SPOE correlation
	synCache    sync.Map // IP string -> time.Time
	synCacheTTL time.Duration

	// SPOE agent
	spoeAgent *spoe.CollectorAgent

	// Metrics server
	metricsServer *http.Server

	// Management API
	managementListener net.Listener

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex
}

// New creates a new Collector
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func New(cfg Config, logger *logrus.Logger) (*Collector, error) {
	c := &Collector{
		Config:             cfg,
		Logger:             logger,
		reconnectCh:        make(chan struct{}, 1),
		signalQueue:        make(chan *apiv1.Signal, max(cfg.SignalQueueSize, 10000)), // Ring buffer default 10k
		synCacheTTL:        60 * time.Second,                                          // TTL for SYN timestamp cache
		prevICMPRates:      make(map[uint32]prevRate),
		prevUDPRates:       make(map[uint32]prevRate),
		prevICMPRatesV6:    make(map[[16]byte]prevRate),
		prevUDPRatesV6:     make(map[[16]byte]prevRate),
		prevBadFlagsSeen:   make(map[uint32]uint64),
		prevBadFlagsSeenV6: make(map[[16]byte]uint64),
		prevEgressBytes:    make(map[uint32]prevEgress),
		prevEgressBytesV6:  make(map[[16]byte]prevEgress),
	}

	// Load GeoIP database
	if cfg.GeoIPASNPath != "" {
		geoIPProvider, err := geoip.New(cfg.GeoIPASNPath, "")
		if err != nil {
			logger.WithError(err).Warn("Failed to load GeoIP database")
		} else {
			c.GeoIP = geoIPProvider
		}
	}

	// Parse allowlist CIDRs
	if cfg.AllowlistCIDRs != "" {
		c.allowedNets = parseAllowlist(cfg.AllowlistCIDRs, logger)
		logger.WithField("count", len(c.allowedNets)).Info("Loaded allowlist CIDRs")
	}

	// Parse per-CIDR policy engine rules
	if cfg.PolicyRules != "" {
		rules, err := parsePolicyRules(cfg.PolicyRules)
		if err != nil {
			logger.WithError(err).Warn("Failed to parse -policy rules; ignoring invalid entries")
		}
		c.policyRules = rules
		logger.WithField("count", len(c.policyRules)).Info("Loaded policy engine rules")
	}

	return c, nil
}

// Start starts the collector
func (c *Collector) Start(ctx context.Context) error {
	c.ctx, c.cancel = context.WithCancel(ctx)

	// PacketYeeter does not implement its own SYN cookie challenge/response:
	// a transparent XDP-layer syncookie would require silently splicing the
	// client's already-"established" connection into a fresh kernel-level
	// handshake, which is not achievable without protocol-breaking hacks
	// (the client would see an unexpected second SYN-ACK). SYN flood
	// mitigation instead relies on the kernel's own, battle-tested
	// implementation via net.ipv4.tcp_syncookies, combined with
	// PacketYeeter's existing incomplete-handshake detection and
	// blocked_ips enforcement to cut off flood traffic before it reaches
	// the backend at all. Warn loudly if the sysctl looks disabled.
	c.checkKernelSynCookies()

	// Load eBPF programs
	c.Logger.Info("Loading eBPF programs...")
	c.Loader = ebpf.NewLoader(c.Config.Interface)
	if err := c.Loader.Load(); err != nil {
		return fmt.Errorf("failed to load eBPF: %w", err)
	}
	if err := c.Loader.Attach(); err != nil {
		return fmt.Errorf("failed to attach eBPF: %w", err)
	}
	c.Maps = c.Loader.GetMaps()
	c.Logger.Info("eBPF programs loaded and attached")

	// Enable kernel-space monitor/dry-run mode if requested. This is
	// independent of the analyzer's own -dry-run flag: it governs whether
	// the collector's own kernel-level detections (bad flags, SYN-flood
	// blocklist, ICMP/UDP rate limits) actually drop traffic.
	if c.Config.DryRun {
		if err := c.Maps.SetMonitorMode(true); err != nil {
			c.Logger.WithError(err).Warn("Failed to enable kernel-space monitor mode; enforcement may still drop traffic")
		} else {
			c.Logger.Warn("Collector running in DRY-RUN / monitor mode: kernel-space detections will log but not drop traffic")
		}
	}

	// Enable per-client egress byte accounting on the TC egress path. This
	// feeds the analyzer's sustained-download detection and is off by default
	// because it costs a map lookup and an atomic add per egress packet.
	if c.Config.EgressAccounting {
		if err := c.Maps.SetEgressAccounting(true); err != nil {
			c.Logger.WithError(err).Warn("Failed to enable egress byte accounting; sustained-download detection will see no volume")
		} else {
			c.Logger.WithField("min_bytes", c.Config.EgressMinBytes).Info("Egress byte accounting enabled")
		}
	}

	// Fragmented UDP / IPv6 fragment policy. Default is RATE (no hard-drop
	// solely for fragmentation). DROP restores the legacy unconditional drop.
	fragMode := c.Config.UDPFragMode
	if fragMode != ebpf.UDPFragModeRate && fragMode != ebpf.UDPFragModeDrop {
		fragMode = ebpf.UDPFragModeRate
	}
	if err := c.Maps.SetUDPFragMode(fragMode); err != nil {
		c.Logger.WithError(err).Warn("Failed to set UDP fragment mode; kernel default applies")
	} else {
		modeName := "rate"
		if fragMode == ebpf.UDPFragModeDrop {
			modeName = "drop"
		}
		c.Logger.WithField("udp_frag_mode", modeName).Info("UDP fragment policy configured")
	}

	// Populate the kernel-space allowlist maps so XDP/TC can bypass
	// allowlisted CIDRs directly, instead of relying solely on the
	// userspace block-decision path.
	if len(c.allowedNets) > 0 {
		if err := c.Maps.SyncAllowlist(c.allowedNets); err != nil {
			c.Logger.WithError(err).Warn("Failed to fully populate kernel-space allowlist maps")
		}
	}

	// Populate the kernel-space per-CIDR policy engine maps (operator
	// block/monitor overrides configured via -policy).
	if len(c.policyRules) > 0 {
		if err := c.Maps.SetPolicies(c.policyRules); err != nil {
			c.Logger.WithError(err).Warn("Failed to fully populate kernel-space policy engine maps")
		} else {
			c.Logger.WithField("count", len(c.policyRules)).Info("Kernel-space policy engine rules active")
		}
	}

	if c.Config.SocketPath != "" {
		if err := c.startManagementSocket(); err != nil {
			return fmt.Errorf("failed to start management socket: %w", err)
		}
	}

	// Start perf event reader for TCP metadata (timestamps, entropy)
	if err := c.startPerfEventReader(); err != nil {
		c.Logger.WithError(err).Warn("Failed to start perf event reader, clock skew and entropy analysis will be unavailable")
	}

	// Start perf event reader for structured kernel-space incident logging
	// (policy blocks, rate-limit drops, bad-flags drops, etc.)
	if err := c.startIncidentReader(); err != nil {
		c.Logger.WithError(err).Warn("Failed to start incident event reader, structured incident logging will be unavailable")
	}

	// Start analyzer connection manager (handles reconnection)
	c.wg.Add(1)
	go c.manageAnalyzerConnection()

	// Start signal sender (drains queue and sends to analyzer)
	c.wg.Add(1)
	go c.signalSender()

	// Start SPOE agent with callbacks
	spoeAddr := c.Config.SPOEAddr
	if spoeAddr == "" {
		spoeAddr = ":9876"
	}
	c.spoeAgent = spoe.NewCollectorAgent(spoeAddr, c.checkAllowlist, spoe.CollectorCallbacks{
		EmitSignal:      c.emitSignal,
		GetSynTimestamp: c.getSynTimestamp, // Pass SYN lookup function
		QueueLen:        func() int { return len(c.signalQueue) },
	})

	// Start map poller (streams raw events to analyzer)
	c.wg.Add(1)
	go c.pollMaps()

	// Start SYN cache cleanup
	c.wg.Add(1)
	go c.cleanupSynCache()

	// Start SPOE
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		if err := c.spoeAgent.Start(); err != nil {
			c.Logger.WithError(err).Error("SPOE agent error")
		}
	}()

	// Start block GC (cleanup expired blocks)
	c.wg.Add(1)
	go c.runBlockGC()

	// Start metrics endpoint (SPOE metrics only)
	c.metricsServer = c.startCollectorMetricsServer()
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.Logger.WithField("addr", c.Config.MetricsAddr).Info("Starting metrics server (SPOE metrics only)")
		if err := c.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			c.Logger.WithError(err).Error("Metrics server error")
		}
	}()

	c.Logger.Info("Collector started")
	return nil
}

const (
	analyzerReconnectInitial = time.Second
	analyzerReconnectMax     = 30 * time.Second
	analyzerConnectionStable = 30 * time.Second
)

func analyzerReconnectBackoff(current, connectedFor time.Duration) (delay, next time.Duration) {
	if current <= 0 || connectedFor >= analyzerConnectionStable {
		current = analyzerReconnectInitial
	}
	return current, min(current*2, analyzerReconnectMax)
}

// waitAnalyzerReconnect sleeps interruptibly before another connection
// attempt. Returning false means the collector is shutting down.
func (c *Collector) waitAnalyzerReconnect(delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-c.ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// manageAnalyzerConnection handles connecting and reconnecting to the analyzer.
func (c *Collector) manageAnalyzerConnection() {
	defer c.wg.Done()

	backoff := analyzerReconnectInitial

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		// Connect to analyzer
		if err := c.connectToAnalyzer(); err != nil {
			delay, next := analyzerReconnectBackoff(backoff, 0)
			c.Logger.WithError(err).WithField("retry_in", delay).Error("Failed to connect to analyzer")
			if !c.waitAnalyzerReconnect(delay) {
				return
			}
			backoff = next
			continue
		}

		connectedAt := time.Now()
		c.connected.Store(true)
		c.Logger.Info("Connected to analyzer")

		// Receive commands until error
		c.receiveCommands()

		// Connection lost
		c.connected.Store(false)
		delay, next := analyzerReconnectBackoff(backoff, time.Since(connectedAt))
		c.Logger.WithField("retry_in", delay).Warn("Lost connection to analyzer, reconnecting...")
		if !c.waitAnalyzerReconnect(delay) {
			return
		}
		backoff = next
	}
}

// connectToAnalyzer establishes connection and stream to the analyzer
func (c *Collector) connectToAnalyzer() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Close existing connection if any
	if c.analyzerConn != nil {
		c.analyzerConn.Close()
		c.analyzerConn = nil
		c.analyzerClient = nil
		c.signalStream = nil
	}

	c.Logger.WithField("addr", c.Config.AnalyzerAddr).Info("Connecting to analyzer...")

	// Create connection with keepalive
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, c.Config.AnalyzerAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                10 * time.Second,
			Timeout:             3 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return fmt.Errorf("failed to dial analyzer: %w", err)
	}

	c.analyzerConn = conn
	c.analyzerClient = apiv1.NewAnalyzerServiceClient(conn)

	// Start bidirectional stream
	stream, err := c.analyzerClient.StreamSignals(c.ctx)
	if err != nil {
		conn.Close()
		c.analyzerConn = nil
		c.analyzerClient = nil
		return fmt.Errorf("failed to start signal stream: %w", err)
	}
	c.signalStream = stream

	return nil
}

// checkAllowlist checks if an IP is in the allowlist
func (c *Collector) checkAllowlist(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}
	c.allowedNetsMu.RLock()
	defer c.allowedNetsMu.RUnlock()
	for _, subnet := range c.allowedNets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

// Stop stops the collector gracefully
func (c *Collector) Stop() {
	c.Logger.Info("Stopping collector...")
	c.cancel()

	c.mu.Lock()
	if c.signalStream != nil {
		c.signalStream.CloseSend()
	}
	if c.analyzerConn != nil {
		c.analyzerConn.Close()
	}
	c.mu.Unlock()

	if c.spoeAgent != nil {
		c.spoeAgent.Stop()
	}

	c.stopManagementSocket()

	// Stop perf event reader
	if c.perfReader != nil {
		c.perfReader.Close()
	}

	// Stop incident event reader
	if c.incidentReader != nil {
		c.incidentReader.Close()
	}

	// Shutdown metrics server
	if c.metricsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.metricsServer.Shutdown(ctx); err != nil {
			c.Logger.WithError(err).Warn("Metrics server shutdown error")
		}
	}

	// Wait for goroutines with timeout. The map-polling and event goroutines
	// still use the eBPF maps and the mmapped GeoIP DB, so those must stay
	// open until the goroutines have drained (closing the GeoIP reader while
	// a Lookup is in flight munmaps memory under it and segfaults).
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		c.Logger.Info("Collector stopped gracefully")
	case <-time.After(10 * time.Second):
		c.Logger.Warn("Shutdown timeout waiting for goroutines")
	}

	if c.Loader != nil {
		c.Loader.Close()
	}
	if c.GeoIP != nil {
		c.GeoIP.Close()
	}
}

// receiveCommands receives block/unblock commands from analyzer
// Returns when the stream breaks (caller should reconnect)
func (c *Collector) receiveCommands() {
	for {
		c.mu.Lock()
		stream := c.signalStream
		c.mu.Unlock()

		if stream == nil {
			return
		}

		cmd, err := stream.Recv()
		if err != nil {
			if c.ctx.Err() != nil {
				return // Context cancelled, shutting down
			}
			c.Logger.WithError(err).Error("Error receiving command from analyzer")
			return // Return to trigger reconnect
		}

		c.executeCommand(cmd)
	}
}

// executeCommand executes a block/unblock command
func (c *Collector) executeCommand(cmd *apiv1.Command) {
	ip := net.IP(cmd.Ip)
	logger := c.Logger.WithFields(logrus.Fields{
		"command": cmd.Type.String(),
		"ip":      ip.String(),
		"reason":  cmd.Reason,
	})

	switch cmd.Type {
	case apiv1.CommandType_COMMAND_BLOCK_IP:
		c.Maps.BlockIP(ip, cmd.Reason, logrus.Fields{
			"source":   cmd.Source,
			"duration": cmd.DurationSeconds,
		})
		logger.Info("Blocked IP by analyzer command")
		metrics.HAProxyBlocks.Inc()

	case apiv1.CommandType_COMMAND_UNBLOCK_IP:
		c.Maps.UnblockIP(ip)
		logger.Info("Unblocked IP by analyzer command")

	case apiv1.CommandType_COMMAND_ALLOWLIST_IP:
		// Add IP to allowlist dynamically
		var ipNet *net.IPNet
		if ip.To4() != nil {
			ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		} else {
			ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
		}
		c.allowedNetsMu.Lock()
		c.allowedNets = append(c.allowedNets, ipNet)
		c.allowedNetsMu.Unlock()
		if err := c.Maps.AddAllowlistEntry(ipNet); err != nil {
			logger.WithError(err).Warn("Failed to add IP to kernel-space allowlist")
		}
		logger.WithField("cidr", ipNet.String()).Info("Added IP to allowlist by analyzer command")

	case apiv1.CommandType_COMMAND_REMOVE_ALLOWLIST_IP:
		// Remove IP from allowlist
		c.allowedNetsMu.Lock()
		filtered := make([]*net.IPNet, 0, len(c.allowedNets))
		removed := make([]*net.IPNet, 0, 1)
		for _, n := range c.allowedNets {
			if !n.IP.Equal(ip) {
				filtered = append(filtered, n)
				continue
			}
			removed = append(removed, n)
		}
		c.allowedNets = filtered
		c.allowedNetsMu.Unlock()
		for _, n := range removed {
			if err := c.Maps.RemoveAllowlistEntry(n); err != nil {
				logger.WithError(err).Warn("Failed to remove IP from kernel-space allowlist")
			}
		}
		logger.Info("Removed IP from allowlist by analyzer command")

	default:
		logger.Warn("Unknown command type")
	}
}

// pollMaps polls eBPF maps and sends raw data to analyzer
func (c *Collector) pollMaps() {
	defer c.wg.Done()

	interval := c.Config.PollInterval
	if interval == 0 {
		interval = time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	c.Logger.WithField("interval", interval).Info("Starting eBPF map poller")

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.Logger.Debug("Polling eBPF maps for signals")
			c.sendPendingHandshakes()
			c.sendICMPRates()
			c.sendUDPRates()
			c.sendBadFlagsAlerts()
			c.sendEgressVolume()
			c.pruneStaleState()
		}
	}
}

// startPerfEventReader initializes and starts the perf event reader for TCP metadata
func (c *Collector) startPerfEventReader() error {
	if c.Maps == nil || c.Maps.Events == nil {
		return fmt.Errorf("events map not available")
	}

	reader, err := perf.NewReader(c.Maps.Events, 4096*16) // 64KB buffer
	if err != nil {
		return fmt.Errorf("failed to create perf reader: %w", err)
	}

	c.perfReader = reader
	c.wg.Add(1)
	go c.readPerfEvents()

	c.Logger.Info("Started perf event reader for TCP metadata (timestamps, entropy)")
	return nil
}

// readPerfEvents reads and processes perf events from eBPF
func (c *Collector) readPerfEvents() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		record, err := c.perfReader.Read()
		if err != nil {
			if c.ctx.Err() != nil {
				return // Shutting down
			}
			c.Logger.WithError(err).Debug("Error reading perf event")
			continue
		}
		c.recordPerfLostSamples("tcp_metadata", record.LostSamples)

		c.processPerfEvent(record.RawSample)
	}
}

// processPerfEvent processes a single perf event containing TCP metadata
func (c *Collector) processPerfEvent(data []byte) {
	var meta ebpf.EventMetadata
	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &meta); err != nil {
		c.Logger.WithError(err).Debug("Failed to parse perf event")
		return
	}

	// Build IP address
	var ip net.IP
	if meta.IsV6 == 1 {
		ip = net.IP(meta.SaddrV6[:])
	} else {
		ipBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(ipBytes, meta.SaddrV4)
		ip = net.IP(ipBytes)
	}

	// Skip allowlisted IPs
	if c.checkAllowlist(ip) {
		return
	}

	// If this is a SYN packet (type=1), store timestamp for later correlation with SPOE
	// TCP flags: SYN=0x02, check if SYN is set and ACK is not (to distinguish from SYN-ACK)
	if meta.Type == 1 && (meta.TcpFlags&0x02) != 0 && (meta.TcpFlags&0x10) == 0 {
		c.storeSynTimestamp(ip)
		c.Logger.WithFields(logrus.Fields{
			"ip":        ip.String(),
			"tcp_flags": fmt.Sprintf("0x%02x", meta.TcpFlags),
		}).Debug("Stored SYN timestamp for eBPF-SPOE correlation")
	}

	// Only process events with timestamp or entropy data
	if meta.HasTimestamp == 0 && meta.EntropyScore == 0 {
		return
	}

	// Get GeoIP
	asn, org := "", ""
	if c.GeoIP != nil {
		asn, org = c.GeoIP.Lookup(ip)
	}

	// Create signal with TCP metadata
	signal := &apiv1.Signal{
		Id:        fmt.Sprintf("tcp-meta-%s-%d", ip.String(), meta.Seq),
		Timestamp: timestamppb.Now(),
		Type:      apiv1.SignalType_SIGNAL_TCP_METADATA,
		Source:    apiv1.SignalSource_SOURCE_EBPF,
		Ip:        ip,
		Asn:       asn,
		Org:       org,
		Weight:    1.0,
		TcpContext: &apiv1.TCPContext{
			TcpTimestamp: meta.TsVal,
			EntropyScore: uint32(meta.EntropyScore),
			Ttl:          uint32(meta.TTL),
			WindowSize:   uint32(meta.Window),
			Mss:          uint32(meta.Mss),
			TcpFlags:     uint32(meta.TcpFlags),
		},
	}

	c.sendSignal(signal)
}

// startIncidentReader initializes and starts the perf event reader for
// structured kernel-space incident logging (policy blocks, blocked-IP
// drops, rate-limit drops, bad-flags drops, fragment drops).
func (c *Collector) startIncidentReader() error {
	if c.Maps == nil || c.Maps.Incidents == nil {
		return fmt.Errorf("incidents map not available")
	}

	reader, err := perf.NewReader(c.Maps.Incidents, 4096*16) // 64KB buffer
	if err != nil {
		return fmt.Errorf("failed to create incident perf reader: %w", err)
	}

	c.incidentReader = reader
	c.wg.Add(1)
	go c.readIncidentEvents()

	c.Logger.Info("Started perf event reader for structured incident logging")
	return nil
}

// readIncidentEvents reads and processes incident events from eBPF
func (c *Collector) readIncidentEvents() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		record, err := c.incidentReader.Read()
		if err != nil {
			if c.ctx.Err() != nil {
				return // Shutting down
			}
			c.Logger.WithError(err).Debug("Error reading incident event")
			continue
		}
		c.recordPerfLostSamples("incidents", record.LostSamples)

		c.processIncidentEvent(record.RawSample)
	}
}

func (c *Collector) recordPerfLostSamples(reader string, lost uint64) {
	if lost == 0 {
		return
	}
	metrics.PerfLostSamples.WithLabelValues(reader).Add(float64(lost))
	c.Logger.WithFields(logrus.Fields{
		"reader":       reader,
		"lost_samples": lost,
	}).Warn("Kernel perf-ring samples lost")
}

// processIncidentEvent decodes a single structured incident event and logs
// it. This is purely a local audit-trail/metrics feature: it does not
// generate an analyzer signal, since the underlying drop conditions
// (bad flags, ICMP/UDP rate limits) already have dedicated signal types.
func (c *Collector) processIncidentEvent(data []byte) {
	var inc ebpf.IncidentEvent
	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &inc); err != nil {
		c.Logger.WithError(err).Debug("Failed to parse incident event")
		return
	}

	var ip net.IP
	if inc.IsV6 == 1 {
		ip = net.IP(inc.SaddrV6[:])
	} else {
		ipBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(ipBytes, inc.SaddrV4)
		ip = net.IP(ipBytes)
	}

	reason := ebpf.IncidentReasonName(inc.Reason)
	metrics.KernelIncidents.WithLabelValues(reason).Inc()

	c.Logger.WithFields(logrus.Fields{
		"ip":               ip.String(),
		"reason":           reason,
		"kernel_timestamp": inc.Timestamp,
	}).Warn("Kernel-space enforcement incident")
}

func (c *Collector) storeSynTimestamp(ip net.IP) {
	c.synCache.Store(ip.String(), time.Now())
}

// getSynTimestamp retrieves and removes the SYN timestamp for an IP
// Returns the timestamp and true if found, otherwise zero time and false
func (c *Collector) getSynTimestamp(ip net.IP) (time.Time, bool) {
	val, ok := c.synCache.LoadAndDelete(ip.String())
	if !ok {
		return time.Time{}, false
	}
	ts, ok := val.(time.Time)
	return ts, ok
}

// cleanupSynCache periodically removes expired entries from the SYN cache
func (c *Collector) cleanupSynCache() {
	defer c.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			expired := 0
			c.synCache.Range(func(key, value interface{}) bool {
				ts, ok := value.(time.Time)
				if ok && now.Sub(ts) > c.synCacheTTL {
					c.synCache.Delete(key)
					expired++
				}
				return true
			})
			if expired > 0 {
				c.Logger.WithField("expired", expired).Debug("Cleaned up expired SYN timestamps")
			}
		}
	}
}

// handshakeRTTNanos returns the SYN->SYN-ACK round-trip for a pending handshake
// and whether it is valid. Entries still awaiting a SYN-ACK have SynAckTime==0,
// so the unsigned SynAckTime-BeginTime subtraction underflows into a huge value
// that, cast to int64, poisons the aggregated handshake RTT.
func handshakeRTTNanos(synAckTime, beginTime uint64) (int64, bool) {
	if synAckTime <= beginTime {
		return 0, false
	}
	return int64(synAckTime - beginTime), true
}

// avgRTTNanos averages accumulated handshake RTTs, returning 0 when no handshake
// in the batch had a valid (completed) RTT rather than dividing by zero.
func avgRTTNanos(totalRTT int64, rttCount int) int64 {
	if rttCount <= 0 {
		return 0
	}
	return totalRTT / int64(rttCount)
}

const pendingHandshakeTimeout = 3 * time.Second

func monotonicNowNS() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	if ts.Sec < 0 || ts.Nsec < 0 {
		return 0, fmt.Errorf("invalid monotonic timestamp: %d.%09d", ts.Sec, ts.Nsec)
	}
	return uint64(ts.Sec)*uint64(time.Second) + uint64(ts.Nsec), nil
}

func pendingHandshakeExpired(nowNS, beginNS uint64) bool {
	if beginNS == 0 || nowNS < beginNS {
		return false
	}
	return nowNS-beginNS >= uint64(pendingHandshakeTimeout)
}

func pendingHandshakeRate(count int, interval time.Duration) float64 {
	if count <= 0 {
		return 0
	}
	if interval <= 0 {
		interval = time.Second
	}
	return float64(count) / interval.Seconds()
}

// sendPendingHandshakes sends incomplete TCP handshakes to analyzer
// once they have remained incomplete for pendingHandshakeTimeout. Consumed
// entries are deleted so map polling cannot turn one missed final ACK into a
// fresh signal every second.
func (c *Collector) sendPendingHandshakes() {
	if c.Maps == nil || c.Maps.PendingHandshakes == nil {
		return
	}

	nowNS, err := monotonicNowNS()
	if err != nil {
		c.Logger.WithError(err).Error("Failed to read monotonic clock for pending handshakes")
		return
	}

	// Aggregate by source IP
	type ipStats struct {
		count    int
		rttCount int // handshakes in the batch with a valid (completed) RTT
		totalRTT int64
		ports    map[uint16]bool
	}
	type pendingIPv4 struct {
		key ebpf.TcpSessionKey
		val ebpf.HandshakeStatusGeneric
	}
	type pendingIPv6 struct {
		key ebpf.TcpSessionKeyV6
		val ebpf.HandshakeStatusGeneric
	}
	ipv4Stats := make(map[uint32]*ipStats)
	const maxBatchSize = 1000 // Limit signals per poll to prevent overwhelming analyzer
	expiredIPv4 := make([]pendingIPv4, 0)
	selectedIPv4 := make(map[uint32]struct{})

	var key ebpf.TcpSessionKey
	var val ebpf.HandshakeStatusGeneric

	iter := c.Maps.PendingHandshakes.Iterate()
	for iter.Next(&key, &val) {
		if !pendingHandshakeExpired(nowNS, val.BeginTime) {
			continue
		}
		if _, ok := selectedIPv4[key.Saddr]; !ok {
			if len(selectedIPv4) >= maxBatchSize {
				continue
			}
			selectedIPv4[key.Saddr] = struct{}{}
		}
		expiredIPv4 = append(expiredIPv4, pendingIPv4{key: key, val: val})
	}
	if err := iter.Err(); err != nil {
		c.Logger.WithError(err).Warn("Failed to iterate IPv4 pending handshakes")
	}

	for _, pending := range expiredIPv4 {
		if err := c.Maps.PendingHandshakes.Delete(&pending.key); err != nil {
			c.Logger.WithError(err).Debug("Failed to consume expired IPv4 pending handshake")
			continue
		}
		stats, ok := ipv4Stats[pending.key.Saddr]
		if !ok {
			stats = &ipStats{ports: make(map[uint16]bool)}
			ipv4Stats[pending.key.Saddr] = stats
		}
		stats.count++
		if rtt, ok := handshakeRTTNanos(pending.val.SynAckTime, pending.val.BeginTime); ok {
			stats.totalRTT += rtt
			stats.rttCount++
		}
		stats.ports[pending.key.Dport] = true
	}

	// Send aggregated signals (one per IP)
	for saddr, stats := range ipv4Stats {
		ipBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(ipBytes, saddr)
		ipAddr := net.IP(ipBytes)

		// Skip allowlisted IPs
		if c.checkAllowlist(ipAddr) {
			continue
		}

		asn, org := "", ""
		if c.GeoIP != nil {
			asn, org = c.GeoIP.Lookup(ipAddr)
		}

		observationWindow := c.Config.PollInterval
		if observationWindow <= 0 {
			observationWindow = time.Second
		}
		weight := pendingHandshakeRate(stats.count, observationWindow)
		if weight > 50000 {
			weight = 50000
		}
		signal := &apiv1.Signal{
			Id:        fmt.Sprintf("tcp-agg-%d", saddr),
			Timestamp: timestamppb.Now(),
			Type:      apiv1.SignalType_SIGNAL_INCOMPLETE_HANDSHAKE,
			Source:    apiv1.SignalSource_SOURCE_EBPF,
			Ip:        ipBytes,
			Asn:       asn,
			Org:       org,
			Weight:    weight, // Use weight to convey count (clamped)
			TcpContext: &apiv1.TCPContext{
				SynCount:       uint32(stats.count),
				HandshakeRttNs: avgRTTNanos(stats.totalRTT, stats.rttCount), // Average RTT over completed handshakes
			},
			Metadata: map[string]string{
				"aggregate_snapshot": "true",
				"handshake_timeout":  pendingHandshakeTimeout.String(),
				"observation_window": observationWindow.String(),
				"pending_count":      fmt.Sprintf("%d", stats.count),
				"unique_ports":       fmt.Sprintf("%d", len(stats.ports)),
			},
		}

		c.sendSignal(signal)
	}

	if len(ipv4Stats) > 0 {
		c.Logger.WithField("count", len(ipv4Stats)).Debug("Sent pending handshake signals (IPv4)")
	}

	// Also send IPv6 (aggregated)
	if c.Maps.PendingHandshakesV6 == nil {
		return
	}

	type ipv6Key [16]byte
	ipv6Stats := make(map[ipv6Key]*ipStats)
	expiredIPv6 := make([]pendingIPv6, 0)
	selectedIPv6 := make(map[ipv6Key]struct{})

	var key6 ebpf.TcpSessionKeyV6
	iter6 := c.Maps.PendingHandshakesV6.Iterate()
	for iter6.Next(&key6, &val) {
		if !pendingHandshakeExpired(nowNS, val.BeginTime) {
			continue
		}
		k := ipv6Key(key6.Saddr)
		if _, ok := selectedIPv6[k]; !ok {
			if len(selectedIPv6) >= maxBatchSize {
				continue
			}
			selectedIPv6[k] = struct{}{}
		}
		expiredIPv6 = append(expiredIPv6, pendingIPv6{key: key6, val: val})
	}
	if err := iter6.Err(); err != nil {
		c.Logger.WithError(err).Warn("Failed to iterate IPv6 pending handshakes")
	}

	for _, pending := range expiredIPv6 {
		if err := c.Maps.PendingHandshakesV6.Delete(&pending.key); err != nil {
			c.Logger.WithError(err).Debug("Failed to consume expired IPv6 pending handshake")
			continue
		}
		k := ipv6Key(pending.key.Saddr)
		stats, ok := ipv6Stats[k]
		if !ok {
			stats = &ipStats{ports: make(map[uint16]bool)}
			ipv6Stats[k] = stats
		}
		stats.count++
		if rtt, ok := handshakeRTTNanos(pending.val.SynAckTime, pending.val.BeginTime); ok {
			stats.totalRTT += rtt
			stats.rttCount++
		}
		stats.ports[pending.key.Dport] = true
	}

	for saddr, stats := range ipv6Stats {
		ipAddr := net.IP(saddr[:])

		// Skip allowlisted IPs
		if c.checkAllowlist(ipAddr) {
			continue
		}

		asn, org := "", ""
		if c.GeoIP != nil {
			asn, org = c.GeoIP.Lookup(ipAddr)
		}

		// Normalize identically to the v4 branch so v4 and v6 handshake
		// weights are comparable.
		observationWindow := c.Config.PollInterval
		if observationWindow <= 0 {
			observationWindow = time.Second
		}
		weight := pendingHandshakeRate(stats.count, observationWindow)
		if weight > 50000 {
			weight = 50000
		}
		signal := &apiv1.Signal{
			Id:        fmt.Sprintf("tcp6-agg-%x", saddr),
			Timestamp: timestamppb.Now(),
			Type:      apiv1.SignalType_SIGNAL_INCOMPLETE_HANDSHAKE,
			Source:    apiv1.SignalSource_SOURCE_EBPF,
			Ip:        saddr[:],
			Asn:       asn,
			Org:       org,
			Weight:    weight,
			TcpContext: &apiv1.TCPContext{
				SynCount:       uint32(stats.count),
				HandshakeRttNs: avgRTTNanos(stats.totalRTT, stats.rttCount),
			},
			Metadata: map[string]string{
				"aggregate_snapshot": "true",
				"handshake_timeout":  pendingHandshakeTimeout.String(),
				"observation_window": observationWindow.String(),
				"pending_count":      fmt.Sprintf("%d", stats.count),
				"unique_ports":       fmt.Sprintf("%d", len(stats.ports)),
			},
		}

		c.sendSignal(signal)
	}
}

// sendICMPRates sends ICMP rate data to analyzer
func (c *Collector) sendICMPRates() {
	if c.Maps == nil {
		return
	}

	sentCount := 0
	totalPPS := 0.0

	if c.Maps.ICMPRates != nil {
		var ip uint32
		var rate ebpf.ICMPRate
		iter := c.Maps.ICMPRates.Iterate()
		for iter.Next(&ip, &rate) {
			if sentCount >= rateMaxBatchSize {
				break
			}
			if rate.Count == 0 {
				continue
			}
			ipBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(ipBytes, ip)
			pps := computePPS(c.prevICMPRates, ip, rate)
			if p, sent := c.emitFloodSignal(net.IP(ipBytes), pps, rate,
				apiv1.SignalType_SIGNAL_ICMP_FLOOD, "icmp"); sent {
				totalPPS += p
				sentCount++
			}
		}
	}

	// IPv6: the XDP program populates icmp_rates_v6 identically to the v4 map;
	// without this loop IPv6 ICMP floods never reach the analyzer. It carries
	// its own per-poll budget (separate from the v4 sentCount) so a concurrent
	// IPv4 flood that fills the v4 batch cannot starve IPv6 emission this poll.
	sentCountV6 := 0
	if c.Maps.ICMPRatesV6 != nil {
		var key [16]byte
		var rate ebpf.ICMPRate
		iter := c.Maps.ICMPRatesV6.Iterate()
		for iter.Next(&key, &rate) {
			if sentCountV6 >= rateMaxBatchSize {
				break
			}
			if rate.Count == 0 {
				continue
			}
			pps := computePPSV6(c.prevICMPRatesV6, key, rate)
			if p, sent := c.emitFloodSignal(net.IP(key[:]), pps, rate,
				apiv1.SignalType_SIGNAL_ICMP_FLOOD, "icmp6"); sent {
				totalPPS += p
				sentCountV6++
			}
		}
	}

	if metrics.ICMPTotalRate != nil {
		metrics.ICMPTotalRate.Set(totalPPS)
	}
	if sent := sentCount + sentCountV6; sent > 0 {
		c.Logger.WithField("count", sent).Debug("Sent ICMP flood signals")
	}
}

// sendUDPRates sends UDP rate data to analyzer
func (c *Collector) sendUDPRates() {
	if c.Maps == nil {
		return
	}

	sentCount := 0
	totalPPS := 0.0

	if c.Maps.UDPRates != nil {
		var ip uint32
		var rate ebpf.ICMPRate // Same struct for UDP
		iter := c.Maps.UDPRates.Iterate()
		for iter.Next(&ip, &rate) {
			if sentCount >= rateMaxBatchSize {
				break
			}
			if rate.Count == 0 {
				continue
			}
			ipBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(ipBytes, ip)
			pps := computePPS(c.prevUDPRates, ip, rate)
			if p, sent := c.emitFloodSignal(net.IP(ipBytes), pps, rate,
				apiv1.SignalType_SIGNAL_UDP_FLOOD, "udp"); sent {
				totalPPS += p
				sentCount++
			}
		}
	}

	// IPv6: mirror the v4 path over udp_rates_v6, which the XDP program
	// populates the same way; otherwise IPv6 UDP floods are never reported. Its
	// own per-poll budget (separate from the v4 sentCount) keeps a concurrent
	// IPv4 flood from starving IPv6 emission this poll.
	sentCountV6 := 0
	if c.Maps.UDPRatesV6 != nil {
		var key [16]byte
		var rate ebpf.ICMPRate
		iter := c.Maps.UDPRatesV6.Iterate()
		for iter.Next(&key, &rate) {
			if sentCountV6 >= rateMaxBatchSize {
				break
			}
			if rate.Count == 0 {
				continue
			}
			pps := computePPSV6(c.prevUDPRatesV6, key, rate)
			if p, sent := c.emitFloodSignal(net.IP(key[:]), pps, rate,
				apiv1.SignalType_SIGNAL_UDP_FLOOD, "udp6"); sent {
				totalPPS += p
				sentCountV6++
			}
		}
	}

	if metrics.UDPTotalRate != nil {
		metrics.UDPTotalRate.Set(totalPPS)
	}
	if sent := sentCount + sentCountV6; sent > 0 {
		c.Logger.WithField("count", sent).Debug("Sent UDP flood signals")
	}
}

// sendBadFlagsAlerts polls the kernel bad_flags/bad_flags_v6 maps (populated
// by the XDP program whenever it detects and drops a SYN+FIN, Xmas, or NULL
// scan packet) and emits a SIGNAL_BAD_FLAGS signal for each newly observed
// scan. Without this, these detections were previously invisible outside
// the kernel: the analyzer already fully supports SIGNAL_BAD_FLAGS, but
// nothing ever produced it.
func (c *Collector) sendBadFlagsAlerts() {
	if c.Maps == nil {
		return
	}

	const maxBatchSize = 1000
	sentCount := 0

	if c.Maps.BadFlags != nil {
		var ip uint32
		var info ebpf.BadFlagsInfo
		iter := c.Maps.BadFlags.Iterate()
		for iter.Next(&ip, &info) {
			if sentCount >= maxBatchSize {
				break
			}
			if info.LastSeen == 0 {
				continue
			}
			if prev, ok := c.prevBadFlagsSeen[ip]; ok && info.LastSeen <= prev {
				continue
			}
			c.prevBadFlagsSeen[ip] = info.LastSeen

			ipBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(ipBytes, ip)
			ipAddr := net.IP(ipBytes)
			if c.checkAllowlist(ipAddr) {
				continue
			}

			asn, org := "", ""
			if c.GeoIP != nil {
				asn, org = c.GeoIP.Lookup(ipAddr)
			}

			c.sendSignal(&apiv1.Signal{
				Id:        fmt.Sprintf("bad-flags-%d-%d", ip, info.LastSeen),
				Timestamp: timestamppb.Now(),
				Type:      apiv1.SignalType_SIGNAL_BAD_FLAGS,
				Source:    apiv1.SignalSource_SOURCE_EBPF,
				Ip:        ipBytes,
				Asn:       asn,
				Org:       org,
				Weight:    10,
				Metadata: map[string]string{
					"scan_type": ebpf.BadFlagsScanName(info.ScanType),
					"flags_raw": fmt.Sprintf("0x%02x", info.FlagsRaw),
				},
			})
			sentCount++
		}
	}

	if c.Maps.BadFlagsV6 != nil {
		type ipv6Key [16]byte
		var saddr ipv6Key
		var info ebpf.BadFlagsInfo
		iter := c.Maps.BadFlagsV6.Iterate()
		for iter.Next(&saddr, &info) {
			if sentCount >= maxBatchSize {
				break
			}
			if info.LastSeen == 0 {
				continue
			}
			if prev, ok := c.prevBadFlagsSeenV6[saddr]; ok && info.LastSeen <= prev {
				continue
			}
			c.prevBadFlagsSeenV6[saddr] = info.LastSeen

			ipAddr := net.IP(saddr[:])
			if c.checkAllowlist(ipAddr) {
				continue
			}

			asn, org := "", ""
			if c.GeoIP != nil {
				asn, org = c.GeoIP.Lookup(ipAddr)
			}

			c.sendSignal(&apiv1.Signal{
				Id:        fmt.Sprintf("bad-flags-v6-%s-%d", ipAddr.String(), info.LastSeen),
				Timestamp: timestamppb.Now(),
				Type:      apiv1.SignalType_SIGNAL_BAD_FLAGS,
				Source:    apiv1.SignalSource_SOURCE_EBPF,
				Ip:        ipAddr,
				Asn:       asn,
				Org:       org,
				Weight:    10,
				Metadata: map[string]string{
					"scan_type": ebpf.BadFlagsScanName(info.ScanType),
					"flags_raw": fmt.Sprintf("0x%02x", info.FlagsRaw),
				},
			})
			sentCount++
		}
	}

	if sentCount > 0 {
		c.Logger.WithField("count", sentCount).Debug("Sent bad TCP flags signals")
	}
}

func computePPS(prev map[uint32]prevRate, ip uint32, rate ebpf.ICMPRate) float64 {
	if prev == nil {
		return float64(rate.Count)
	}
	pr, ok := prev[ip]
	prev[ip] = prevRate{lastTime: rate.LastTime, count: rate.Count}
	return ppsFromWindow(pr, ok, rate)
}

// computePPSV6 mirrors computePPS for the [16]byte-keyed IPv6 rate maps.
func computePPSV6(prev map[[16]byte]prevRate, ip [16]byte, rate ebpf.ICMPRate) float64 {
	if prev == nil {
		return float64(rate.Count)
	}
	pr, ok := prev[ip]
	prev[ip] = prevRate{lastTime: rate.LastTime, count: rate.Count}
	return ppsFromWindow(pr, ok, rate)
}

// ppsFromWindow derives a pps estimate from the current and previous window
// samples, shared by the v4 and v6 computePPS variants.
func ppsFromWindow(pr prevRate, ok bool, rate ebpf.ICMPRate) float64 {
	if !ok {
		return float64(rate.Count)
	}
	if rate.LastTime == pr.lastTime {
		return float64(rate.Count)
	}
	if rate.LastTime > pr.lastTime && rate.Count < pr.count {
		// Window rolled; use previous window's peak count
		return float64(pr.count)
	}
	return float64(rate.Count)
}

// The kernel rate/bad-flags maps are LRU_HASH and self-evict under churn, but
// the userspace bookkeeping maps that shadow them (prevICMPRates, prevUDPRates,
// their IPv6 variants, and prevBadFlagsSeen/prevBadFlagsSeenV6) are plain Go
// maps that would otherwise grow for the process lifetime: every distinct
// source ever observed leaves an entry behind even after the kernel forgets it.
// Under a high-cardinality spoofed-source flood that is an unbounded memory
// leak, and it leaves the IPv6 shadows growing while the IPv4 ones are bounded.
//
// pruneStaleState bounds them the same way the kernel does. Entry values carry
// the kernel monotonic timestamp (bpf_ktime_get_ns) of when the source was last
// seen, so the largest timestamp across all maps approximates "now" on the
// kernel clock. Anything older than prevStateStaleWindowNs is dropped. A hard
// per-map cap is a final safety valve against adversarial cardinality bursts
// faster than the window: if a map still exceeds it, the map is reset, which at
// worst re-emits already-deduplicated signals for one poll cycle.
const (
	prevStateStaleWindowNs uint64 = 300 * 1_000_000_000 // 5 minutes of kernel monotonic time
	prevStateHardCap              = 1 << 18             // 262144 entries per map
)

func (c *Collector) pruneStaleState() {
	maxClock := uint64(0)
	for _, v := range c.prevICMPRates {
		if v.lastTime > maxClock {
			maxClock = v.lastTime
		}
	}
	for _, v := range c.prevUDPRates {
		if v.lastTime > maxClock {
			maxClock = v.lastTime
		}
	}
	for _, v := range c.prevICMPRatesV6 {
		if v.lastTime > maxClock {
			maxClock = v.lastTime
		}
	}
	for _, v := range c.prevUDPRatesV6 {
		if v.lastTime > maxClock {
			maxClock = v.lastTime
		}
	}
	for _, ts := range c.prevBadFlagsSeen {
		if ts > maxClock {
			maxClock = ts
		}
	}
	for _, ts := range c.prevBadFlagsSeenV6 {
		if ts > maxClock {
			maxClock = ts
		}
	}

	prunePrevRateMap(c.prevICMPRates, maxClock, c.Logger)
	prunePrevRateMap(c.prevUDPRates, maxClock, c.Logger)
	prunePrevRateMapV6(c.prevICMPRatesV6, maxClock, c.Logger)
	prunePrevRateMapV6(c.prevUDPRatesV6, maxClock, c.Logger)
	prunePrevSeenMap(c.prevBadFlagsSeen, maxClock, c.Logger)
	prunePrevSeenMap(c.prevBadFlagsSeenV6, maxClock, c.Logger)
	c.pruneEgressState(time.Now())
}

func prunePrevRateMap(m map[uint32]prevRate, maxClock uint64, logger *logrus.Logger) {
	if maxClock > prevStateStaleWindowNs {
		cutoff := maxClock - prevStateStaleWindowNs
		for k, v := range m {
			if v.lastTime < cutoff {
				delete(m, k)
			}
		}
	}
	if len(m) > prevStateHardCap {
		if logger != nil {
			logger.WithField("size", len(m)).Warn("prev-rate state exceeded hard cap under high cardinality; resetting")
		}
		for k := range m {
			delete(m, k)
		}
	}
}

func prunePrevRateMapV6(m map[[16]byte]prevRate, maxClock uint64, logger *logrus.Logger) {
	if maxClock > prevStateStaleWindowNs {
		cutoff := maxClock - prevStateStaleWindowNs
		for k, v := range m {
			if v.lastTime < cutoff {
				delete(m, k)
			}
		}
	}
	if len(m) > prevStateHardCap {
		if logger != nil {
			logger.WithField("size", len(m)).Warn("prev-rate v6 state exceeded hard cap under high cardinality; resetting")
		}
		for k := range m {
			delete(m, k)
		}
	}
}

func prunePrevSeenMap[K comparable](m map[K]uint64, maxClock uint64, logger *logrus.Logger) {
	if maxClock > prevStateStaleWindowNs {
		cutoff := maxClock - prevStateStaleWindowNs
		for k, ts := range m {
			if ts < cutoff {
				delete(m, k)
			}
		}
	}
	if len(m) > prevStateHardCap {
		if logger != nil {
			logger.WithField("size", len(m)).Warn("prev-seen state exceeded hard cap under high cardinality; resetting")
		}
		for k := range m {
			delete(m, k)
		}
	}
}

// floodRateParams bundles the constants shared by the ICMP/UDP rate readers.
const (
	rateMaxBatchSize = 1000   // Limit signals per poll
	rateMinFloodPPS  = 1000.0 // Avoid false positives on legitimate bursts
)

// emitFloodSignal applies the allowlist and pps-threshold gates and, if the
// source qualifies, builds and sends one flood signal. It returns the pps it
// contributed (0 when skipped) and whether a signal was sent, so v4 and v6
// callers share identical gating and cannot drift apart.
func (c *Collector) emitFloodSignal(ipAddr net.IP, pps float64, rate ebpf.ICMPRate, sigType apiv1.SignalType, idPrefix string) (float64, bool) {
	if c.checkAllowlist(ipAddr) {
		return 0, false
	}
	if pps < rateMinFloodPPS {
		return 0, false
	}
	// The rate-map iterators reuse a single key buffer across iterations and
	// signals are marshaled asynchronously off signalQueue, so the address must
	// be copied before it is retained; aliasing ipAddr ships every signal with
	// the last-iterated source IP. Formatting the id here (post-gate) also keeps
	// the per-entry string allocation off the sub-threshold/allowlisted paths.
	ip := append(net.IP(nil), ipAddr...)
	asn, org := "", ""
	if c.GeoIP != nil {
		asn, org = c.GeoIP.Lookup(ip)
	}
	c.sendSignal(&apiv1.Signal{
		Id:        idPrefix + "-" + ip.String(),
		Timestamp: timestamppb.Now(),
		Type:      sigType,
		Source:    apiv1.SignalSource_SOURCE_EBPF,
		Ip:        ip,
		Asn:       asn,
		Org:       org,
		Weight:    pps,
		Metadata: map[string]string{
			"count":     fmt.Sprintf("%d", rate.Count),
			"last_time": fmt.Sprintf("%d", rate.LastTime),
			"pps":       fmt.Sprintf("%.2f", pps),
		},
	})
	return pps, true
}

// runBlockGC garbage collects expired blocks from eBPF maps
func (c *Collector) runBlockGC() {
	defer c.wg.Done()

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.gcExpiredBlocks()
		}
	}
}

// gcExpiredBlocks removes expired blocks from eBPF maps
func (c *Collector) gcExpiredBlocks() {
	if c.Maps == nil || c.Maps.BlockedIPs == nil {
		return
	}

	// ListBlockedIPs returns IPs with remaining TTL - we delete those with "expired" TTL
	v4List, v6List := c.Maps.ListBlockedIPs(c.Config.BlockDuration)

	for _, info := range v4List {
		if info.RemainingTTL == "expired" {
			ip := net.ParseIP(info.IP)
			if ip != nil {
				c.Maps.UnblockIP(ip)
				c.Logger.WithField("ip", info.IP).Debug("GC: Unblocked expired IP")
			}
		}
	}
	for _, info := range v6List {
		if info.RemainingTTL == "expired" {
			ip := net.ParseIP(info.IP)
			if ip != nil {
				c.Maps.UnblockIP(ip)
				c.Logger.WithField("ip", info.IP).Debug("GC: Unblocked expired IPv6")
			}
		}
	}
}

// sendSignal sends a signal to the analyzer (thread-safe)
func (c *Collector) sendSignal(signal *apiv1.Signal) {
	// Fast path: non-blocking enqueue.
	select {
	case c.signalQueue <- signal:
		c.recordSignalQueued()
		return
	default:
	}

	// Queue full. Make room by dropping the oldest, then retry the enqueue
	// exactly once - still non-blocking. Concurrent producers (the poll loop,
	// perf/incident readers, and synchronous SPOE callbacks all call
	// sendSignal) may refill the slot we just freed before our retry runs. The
	// previous implementation used an unconditional `c.signalQueue <- signal`
	// here, which blocks in exactly that race - stalling a synchronous SPOE
	// callback, and with it HAProxy request handling and shutdown. Instead we
	// drop THIS signal if the retry can't proceed: under sustained overload we
	// always shed load rather than apply backpressure to the caller, which is
	// the intended ring-buffer semantics.
	select {
	case <-c.signalQueue: // Drop oldest
		c.recordSignalDrop()
	default:
		// Already drained by another producer; fall through to the retry.
	}

	select {
	case c.signalQueue <- signal:
		c.recordSignalQueued()
	default:
		c.recordSignalDrop()
	}
}

func (c *Collector) recordSignalQueued() {
	ql := len(c.signalQueue)
	metrics.CollectorSignalQueueDepth.Set(float64(ql))
	if c.Logger != nil && c.Logger.IsLevelEnabled(logrus.DebugLevel) {
		c.Logger.WithField("queue_len", ql).Debug("Signal queued")
	}
}

func (c *Collector) recordSignalDrop() {
	metrics.CollectorSignalQueueDrops.Inc()
	c.dropLogMu.Lock()
	c.dropLogCount++
	if time.Since(c.dropLogLast) > 5*time.Second {
		c.Logger.WithField("drops", c.dropLogCount).Warn("Signal queue full, dropped signals")
		c.dropLogLast = time.Now()
		c.dropLogCount = 0
	}
	c.dropLogMu.Unlock()
}

// signalSendTimeout bounds how long signalSender waits for a single
// stream.Send() call to the analyzer before treating the connection as
// stuck and forcing a reconnect. Without this, a stalled/slow-reading
// analyzer can block the single sender goroutine indefinitely: the
// signal queue then fills up silently ("queuing but not processing")
// while manageAnalyzerConnection never notices anything is wrong, since
// it only detects disconnects via a failing stream.Recv().
const signalSendTimeout = 2 * time.Second

// signalSender drains the signal queue and sends to analyzer
func (c *Collector) signalSender() {
	defer c.wg.Done()

	c.Logger.Info("Signal sender goroutine started")

	depthTicker := time.NewTicker(time.Second)
	defer depthTicker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			c.Logger.Info("Signal sender stopping")
			return
		case <-depthTicker.C:
			metrics.SPOEQueueDepth.Set(float64(len(c.signalQueue)))
		case signal := <-c.signalQueue:
			if !c.connected.Load() {
				c.Logger.Debug("Not connected to analyzer, skipping signal")
				continue // Not connected, skip
			}

			// Copy the stream reference under the lock, then send
			// outside of it. Holding c.mu across the (potentially
			// blocking) Send() call would also block connectToAnalyzer
			// and Stop() from acquiring the same mutex, preventing any
			// reconnect from ever happening while a send is stuck.
			c.mu.Lock()
			stream := c.signalStream
			c.mu.Unlock()
			if stream == nil {
				continue
			}

			start := time.Now()
			if err := c.sendSignalWithTimeout(stream, signal, signalSendTimeout); err != nil {
				c.Logger.WithError(err).Warn("Failed to send signal to analyzer")
				if errors.Is(err, errSignalSendTimedOut) {
					// The stream appears stuck (e.g. analyzer stopped
					// reading). Tear down the connection so
					// manageAnalyzerConnection redials immediately
					// instead of silently backlogging the queue.
					c.resetAnalyzerConnection()
				}
			} else {
				c.Logger.WithFields(logrus.Fields{
					"type": signal.Type.String(),
					"ip":   net.IP(signal.Ip).String(),
				}).Debug("Signal sent to analyzer")
			}
			metrics.SPOEProcessingLatency.Observe(time.Since(start).Seconds())
		}
	}
}

var errSignalSendTimedOut = errors.New("timed out sending signal to analyzer")

// sendSignalWithTimeout calls stream.Send in a goroutine and bounds how
// long we wait for it to return. gRPC's ClientStream.Send does not accept
// a per-call context/deadline, so this is the only way to detect a stuck
// send without blocking the sender goroutine forever.
func (c *Collector) sendSignalWithTimeout(stream apiv1.AnalyzerService_StreamSignalsClient, signal *apiv1.Signal, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		done <- stream.Send(signal)
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return errSignalSendTimedOut
	}
}

// resetAnalyzerConnection tears down the current analyzer connection so
// manageAnalyzerConnection's loop redials on its next iteration, instead
// of waiting for a Recv() error that may never come while Send() is
// wedged on a half-broken stream.
func (c *Collector) resetAnalyzerConnection() {
	c.mu.Lock()
	if c.analyzerConn != nil {
		c.analyzerConn.Close()
		c.analyzerConn = nil
		c.analyzerClient = nil
		c.signalStream = nil
	}
	c.mu.Unlock()
	c.connected.Store(false)
}

// SPOE callback implementations - these forward to analyzer

func (c *Collector) emitSignal(signal *apiv1.Signal) {
	c.sendSignal(signal)
}

// startCollectorMetricsServer creates a metrics server that only exposes SPOE-related metrics
func (c *Collector) startCollectorMetricsServer() *http.Server {
	// Create a custom registry that only includes SPOE handler metrics
	registry := prometheus.NewRegistry()

	// Register only SPOE handler/queue metrics (not analysis metrics)
	registry.MustRegister(metrics.SPOEHandlerLatency)
	registry.MustRegister(metrics.SPOEQueueDepth)
	registry.MustRegister(metrics.SPOEQueueDrops)
	registry.MustRegister(metrics.SPOEProcessingLatency)
	registry.MustRegister(metrics.KernelIncidents)
	registry.MustRegister(metrics.PerfLostSamples)
	metrics.PerfLostSamples.WithLabelValues("tcp_metadata").Add(0)
	metrics.PerfLostSamples.WithLabelValues("incidents").Add(0)

	// Egress accounting is produced by this process, so it is only ever
	// observable here -- the analyzer's registry would report a constant 0.
	registry.MustRegister(metrics.EgressVolumeSignals)
	registry.MustRegister(metrics.EgressBytesReported)

	// Create HTTP handler with custom registry
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

	return &http.Server{
		Addr:    c.Config.MetricsAddr,
		Handler: mux,
		// The default addr binds all interfaces; without timeouts a
		// slowloris client trickling header bytes pins goroutines and fds
		// indefinitely.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
}

// parseAllowlist parses comma-separated CIDR strings into IPNet slices
func parseAllowlist(cidrs string, logger *logrus.Logger) []*net.IPNet {
	if cidrs == "" {
		return nil
	}

	var nets []*net.IPNet
	for _, cidr := range strings.Split(cidrs, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}

		// Handle single IPs without /prefix
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr = cidr + "/128" // IPv6
			} else {
				cidr = cidr + "/32" // IPv4
			}
		}

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			logger.WithError(err).WithField("cidr", cidr).Warn("Invalid CIDR in allowlist")
			continue
		}
		nets = append(nets, ipNet)
		logger.WithField("cidr", cidr).Debug("Added to allowlist")
	}

	return nets
}

// parsePolicyRules parses -policy flag values of the form
// "CIDR=action,CIDR=action,..." (action = "block" or "monitor") into
// ebpf.PolicyRule entries. "=" is used (not ":") because IPv6 addresses
// contain colons, which would make CIDR:action ambiguous to split.
// Invalid entries are skipped with an error collected via errors.Join;
// parsing continues so a single typo doesn't silently disable every rule.
func parsePolicyRules(spec string) ([]ebpf.PolicyRule, error) {
	if spec == "" {
		return nil, nil
	}

	var rules []ebpf.PolicyRule
	var errs []error
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		idx := strings.LastIndex(entry, "=")
		if idx < 0 {
			errs = append(errs, fmt.Errorf("invalid policy entry %q (want CIDR=action)", entry))
			continue
		}
		cidr := strings.TrimSpace(entry[:idx])
		actionStr := strings.TrimSpace(entry[idx+1:])

		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr = cidr + "/128"
			} else {
				cidr = cidr + "/32"
			}
		}

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid CIDR %q in policy entry %q: %w", entry[:idx], entry, err))
			continue
		}

		action, err := ebpf.ParsePolicyAction(actionStr)
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid policy entry %q: %w", entry, err))
			continue
		}

		rules = append(rules, ebpf.PolicyRule{Net: ipNet, Action: action})
	}

	return rules, errors.Join(errs...)
}
