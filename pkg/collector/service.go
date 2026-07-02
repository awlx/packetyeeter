package collector

import (
	"bytes"
	"context"
	"encoding/binary"
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
	HAProxyPort     int
	SocketPath      string
	GeoIPASNPath    string
	AllowlistCIDRs  string // Comma-separated CIDRs
	BlockDuration   time.Duration
	PollInterval    time.Duration // How often to poll eBPF maps and send to analyzer
	SignalQueueSize int           // Collector signal queue size (default 10000)
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
	Loader      *ebpf.Loader
	Maps        *ebpf.Maps
	GeoIP       *geoip.Provider
	Logger      *logrus.Logger
	allowedNets []*net.IPNet
	perfReader  *perf.Reader

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
	prevICMPRates map[uint32]prevRate
	prevUDPRates  map[uint32]prevRate

	// SYN timestamp cache for eBPF <-> SPOE correlation
	synCache    sync.Map // IP string -> time.Time
	synCacheTTL time.Duration

	// SPOE agent
	spoeAgent *spoe.CollectorAgent

	// Metrics server
	metricsServer *http.Server

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
		Config:        cfg,
		Logger:        logger,
		reconnectCh:   make(chan struct{}, 1),
		signalQueue:   make(chan *apiv1.Signal, max(cfg.SignalQueueSize, 10000)), // Ring buffer default 10k
		synCacheTTL:   60 * time.Second,                                          // TTL for SYN timestamp cache
		prevICMPRates: make(map[uint32]prevRate),
		prevUDPRates:  make(map[uint32]prevRate),
	}

	// Load GeoIP database
	if cfg.GeoIPASNPath != "" {
		geoIPProvider, err := geoip.New(cfg.GeoIPASNPath)
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

	return c, nil
}

// Start starts the collector
func (c *Collector) Start(ctx context.Context) error {
	c.ctx, c.cancel = context.WithCancel(ctx)

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

	// Start perf event reader for TCP metadata (timestamps, entropy)
	if err := c.startPerfEventReader(); err != nil {
		c.Logger.WithError(err).Warn("Failed to start perf event reader, clock skew and entropy analysis will be unavailable")
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

// manageAnalyzerConnection handles connecting and reconnecting to the analyzer
func (c *Collector) manageAnalyzerConnection() {
	defer c.wg.Done()

	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		// Connect to analyzer
		if err := c.connectToAnalyzer(); err != nil {
			c.Logger.WithError(err).WithField("retry_in", backoff).Error("Failed to connect to analyzer")
			select {
			case <-c.ctx.Done():
				return
			case <-time.After(backoff):
				backoff = min(backoff*2, maxBackoff)
				continue
			}
		}

		// Reset backoff on successful connection
		backoff = time.Second
		c.connected.Store(true)
		c.Logger.Info("Connected to analyzer")

		// Receive commands until error
		c.receiveCommands()

		// Connection lost
		c.connected.Store(false)
		c.Logger.Warn("Lost connection to analyzer, reconnecting...")
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

	// Stop perf event reader
	if c.perfReader != nil {
		c.perfReader.Close()
	}

	// Shutdown metrics server
	if c.metricsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.metricsServer.Shutdown(ctx); err != nil {
			c.Logger.WithError(err).Warn("Metrics server shutdown error")
		}
	}

	if c.Loader != nil {
		c.Loader.Close()
	}
	if c.GeoIP != nil {
		c.GeoIP.Close()
	}

	// Wait for goroutines with timeout
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
		c.allowedNets = append(c.allowedNets, ipNet)
		logger.WithField("cidr", ipNet.String()).Info("Added IP to allowlist by analyzer command")

	case apiv1.CommandType_COMMAND_REMOVE_ALLOWLIST_IP:
		// Remove IP from allowlist
		filtered := make([]*net.IPNet, 0, len(c.allowedNets))
		for _, n := range c.allowedNets {
			if !n.IP.Equal(ip) {
				filtered = append(filtered, n)
			}
		}
		c.allowedNets = filtered
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
		},
		Metadata: map[string]string{
			"has_timestamp": fmt.Sprintf("%d", meta.HasTimestamp),
			"tcp_flags":     fmt.Sprintf("0x%02x", meta.TcpFlags),
			"event_type":    fmt.Sprintf("%d", meta.Type),
		},
	}

	c.sendSignal(signal)
}

// storeSynTimestamp stores the timestamp when a SYN packet is seen
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

// sendPendingHandshakes sends incomplete TCP handshakes to analyzer
// Aggregates by source IP to avoid flooding the analyzer
func (c *Collector) sendPendingHandshakes() {
	if c.Maps == nil || c.Maps.PendingHandshakes == nil {
		return
	}

	// Aggregate by source IP
	type ipStats struct {
		count    int
		totalRTT int64
		ports    map[uint16]bool
	}
	ipv4Stats := make(map[uint32]*ipStats)
	const maxBatchSize = 1000 // Limit signals per poll to prevent overwhelming analyzer

	var key ebpf.TcpSessionKey
	var val ebpf.HandshakeStatusGeneric

	iter := c.Maps.PendingHandshakes.Iterate()
	for iter.Next(&key, &val) {
		stats, ok := ipv4Stats[key.Saddr]
		if !ok {
			// Stop aggregating if we hit batch size limit
			if len(ipv4Stats) >= maxBatchSize {
				break
			}
			stats = &ipStats{ports: make(map[uint16]bool)}
			ipv4Stats[key.Saddr] = stats
		}
		stats.count++
		stats.totalRTT += int64(val.SynAckTime - val.BeginTime)
		stats.ports[key.Dport] = true
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

		pollSec := c.Config.PollInterval.Seconds()
		if pollSec == 0 {
			pollSec = 1
		}
		weight := float64(stats.count) / pollSec // pps approximation
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
				HandshakeRttNs: stats.totalRTT / int64(stats.count), // Average RTT
			},
			Metadata: map[string]string{
				"pending_count": fmt.Sprintf("%d", stats.count),
				"unique_ports":  fmt.Sprintf("%d", len(stats.ports)),
			},
		}

		c.sendSignal(signal)
	}

	if len(ipv4Stats) > 0 {
		c.Logger.WithField("count", len(ipv4Stats)).Debug("Sent pending handshake signals (IPv4)")
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

	var key6 ebpf.TcpSessionKeyV6
	iter6 := c.Maps.PendingHandshakesV6.Iterate()
	for iter6.Next(&key6, &val) {
		k := ipv6Key(key6.Saddr)
		stats, ok := ipv6Stats[k]
		if !ok {
			// Stop aggregating if we hit batch size limit
			if len(ipv6Stats) >= maxBatchSize {
				break
			}
			stats = &ipStats{ports: make(map[uint16]bool)}
			ipv6Stats[k] = stats
		}
		stats.count++
		stats.totalRTT += int64(val.SynAckTime - val.BeginTime)
		stats.ports[key6.Dport] = true
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

		signal := &apiv1.Signal{
			Id:        fmt.Sprintf("tcp6-agg-%x", saddr),
			Timestamp: timestamppb.Now(),
			Type:      apiv1.SignalType_SIGNAL_INCOMPLETE_HANDSHAKE,
			Source:    apiv1.SignalSource_SOURCE_EBPF,
			Ip:        saddr[:],
			Asn:       asn,
			Org:       org,
			Weight:    float64(stats.count),
			TcpContext: &apiv1.TCPContext{
				SynCount:       uint32(stats.count),
				HandshakeRttNs: stats.totalRTT / int64(stats.count),
			},
			Metadata: map[string]string{
				"pending_count": fmt.Sprintf("%d", stats.count),
				"unique_ports":  fmt.Sprintf("%d", len(stats.ports)),
			},
		}

		c.sendSignal(signal)
	}
}

// sendICMPRates sends ICMP rate data to analyzer
func (c *Collector) sendICMPRates() {
	if c.Maps == nil || c.Maps.ICMPRates == nil {
		return
	}

	const maxBatchSize = 1000  // Limit signals per poll
	const minFloodPPS = 1000.0 // Raised to 1000 - avoid false positives on legitimate bursts
	sentCount := 0
	totalPPS := 0.0

	var ip uint32
	var rate ebpf.ICMPRate

	iter := c.Maps.ICMPRates.Iterate()
	for iter.Next(&ip, &rate) {
		if rate.Count == 0 {
			continue
		}

		// Stop if we hit batch size limit
		if sentCount >= maxBatchSize {
			break
		}

		ipBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(ipBytes, ip)
		ipAddr := net.IP(ipBytes)

		// Skip allowlisted IPs
		if c.checkAllowlist(ipAddr) {
			continue
		}

		asn, org := "", ""
		if c.GeoIP != nil {
			asn, org = c.GeoIP.Lookup(ipAddr)
		}

		pps := computePPS(c.prevICMPRates, ip, rate)
		if pps < minFloodPPS {
			continue
		}
		totalPPS += pps

		signal := &apiv1.Signal{
			Id:        fmt.Sprintf("icmp-%d", ip),
			Timestamp: timestamppb.Now(),
			Type:      apiv1.SignalType_SIGNAL_ICMP_FLOOD,
			Source:    apiv1.SignalSource_SOURCE_EBPF,
			Ip:        ipBytes,
			Asn:       asn,
			Org:       org,
			Weight:    pps,
			Metadata: map[string]string{
				"count":     fmt.Sprintf("%d", rate.Count),
				"last_time": fmt.Sprintf("%d", rate.LastTime),
				"pps":       fmt.Sprintf("%.2f", pps),
			},
		}

		c.sendSignal(signal)
		sentCount++
	}

	if metrics.ICMPTotalRate != nil {
		metrics.ICMPTotalRate.Set(totalPPS)
	}
	if sentCount > 0 {
		c.Logger.WithField("count", sentCount).Debug("Sent ICMP flood signals")
	}
}

// sendUDPRates sends UDP rate data to analyzer
func (c *Collector) sendUDPRates() {
	if c.Maps == nil || c.Maps.UDPRates == nil {
		return
	}

	const maxBatchSize = 1000  // Limit signals per poll
	const minFloodPPS = 1000.0 // Raised to 1000 - avoid false positives on legitimate bursts
	sentCount := 0
	totalPPS := 0.0

	var ip uint32
	var rate ebpf.ICMPRate // Same struct for UDP

	iter := c.Maps.UDPRates.Iterate()
	for iter.Next(&ip, &rate) {
		if rate.Count == 0 {
			continue
		}

		// Stop if we hit batch size limit
		if sentCount >= maxBatchSize {
			break
		}

		ipBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(ipBytes, ip)
		ipAddr := net.IP(ipBytes)

		// Skip allowlisted IPs
		if c.checkAllowlist(ipAddr) {
			continue
		}

		asn, org := "", ""
		if c.GeoIP != nil {
			asn, org = c.GeoIP.Lookup(ipAddr)
		}

		pps := computePPS(c.prevUDPRates, ip, rate)
		if pps < minFloodPPS {
			continue
		}
		totalPPS += pps

		signal := &apiv1.Signal{
			Id:        fmt.Sprintf("udp-%d", ip),
			Timestamp: timestamppb.Now(),
			Type:      apiv1.SignalType_SIGNAL_UDP_FLOOD,
			Source:    apiv1.SignalSource_SOURCE_EBPF,
			Ip:        ipBytes,
			Asn:       asn,
			Org:       org,
			Weight:    pps,
			Metadata: map[string]string{
				"count":     fmt.Sprintf("%d", rate.Count),
				"last_time": fmt.Sprintf("%d", rate.LastTime),
				"pps":       fmt.Sprintf("%.2f", pps),
			},
		}

		c.sendSignal(signal)
		sentCount++
	}
}

// computePPS approximates pps using monotonic last_time windows. If the window rolled (lastTime increased and count reset), return previous window peak.
func computePPS(prev map[uint32]prevRate, ip uint32, rate ebpf.ICMPRate) float64 {
	if prev == nil {
		return float64(rate.Count)
	}
	pr, ok := prev[ip]
	prev[ip] = prevRate{lastTime: rate.LastTime, count: rate.Count}
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
	// Try to send to queue (non-blocking)
	select {
	case c.signalQueue <- signal:
		// Successfully queued
		ql := len(c.signalQueue)
		metrics.CollectorSignalQueueDepth.Set(float64(ql))
		if c.Logger != nil && c.Logger.IsLevelEnabled(logrus.DebugLevel) {
			c.Logger.WithField("queue_len", ql).Debug("Signal queued")
		}
	default:
		// Queue full - drop oldest and add new (ring buffer behavior)
		select {
		case <-c.signalQueue: // Drop oldest
			c.signalQueue <- signal // Add new
			metrics.CollectorSignalQueueDrops.Inc()
			c.dropLogMu.Lock()
			c.dropLogCount++
			if time.Since(c.dropLogLast) > 5*time.Second {
				c.Logger.WithField("drops", c.dropLogCount).Warn("Signal queue full, dropped oldest signals")
				c.dropLogLast = time.Now()
				c.dropLogCount = 0
			}
			c.dropLogMu.Unlock()
		default:
		}
	}
}

// signalSender drains the signal queue and sends to analyzer
func (c *Collector) signalSender() {
	defer c.wg.Done()

	c.Logger.Info("Signal sender goroutine started")

	for {
		select {
		case <-c.ctx.Done():
			c.Logger.Info("Signal sender stopping")
			return
		case signal := <-c.signalQueue:
			if !c.connected.Load() {
				c.Logger.Debug("Not connected to analyzer, skipping signal")
				continue // Not connected, skip
			}

			start := time.Now()
			c.mu.Lock()
			if c.signalStream != nil {
				if err := c.signalStream.Send(signal); err != nil {
					c.Logger.WithError(err).Warn("Failed to send signal to analyzer")
				} else {
					c.Logger.WithFields(logrus.Fields{
						"type": signal.Type.String(),
						"ip":   net.IP(signal.Ip).String(),
					}).Debug("Signal sent to analyzer")
				}
			}
			c.mu.Unlock()
			metrics.SPOEProcessingLatency.Observe(time.Since(start).Seconds())
		}
	}
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

	// Create HTTP handler with custom registry
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

	return &http.Server{
		Addr:    c.Config.MetricsAddr,
		Handler: mux,
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
