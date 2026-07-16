package spoe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/negasus/haproxy-spoe-go/agent"
	"github.com/negasus/haproxy-spoe-go/logger"
	"github.com/negasus/haproxy-spoe-go/request"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/metrics"
)

// CollectorCallbacks defines callbacks the collector provides to the SPOE agent
type CollectorCallbacks struct {
	// EmitSignal sends a signal to the analyzer
	EmitSignal func(*apiv1.Signal)
	// GetSynTimestamp retrieves the SYN timestamp for an IP (for RTT calculation)
	GetSynTimestamp func(net.IP) (time.Time, bool)
	// QueueLen returns current signal queue length (optional)
	QueueLen func() int
}

// CollectorAgent is the SPOE agent for the collector daemon
// It sends signals to the analyzer rather than processing them locally
type CollectorAgent struct {
	addr        string
	stop        chan struct{}
	checkConfig func(net.IP) bool // allowlist check
	callbacks   CollectorCallbacks
	server      *agent.Agent
	listener    net.Listener
}

// NewCollectorAgent creates a new SPOE agent for the collector daemon
func NewCollectorAgent(addr string, checkConfig func(net.IP) bool, callbacks CollectorCallbacks) *CollectorAgent {
	return &CollectorAgent{
		addr:        addr,
		stop:        make(chan struct{}),
		checkConfig: checkConfig,
		callbacks:   callbacks,
	}
}

// Start launches the SPOP server
func (a *CollectorAgent) Start() error {
	handler := func(req *request.Request) {
		start := time.Now()
		defer func() {
			dur := time.Since(start).Seconds()
			metrics.SPOEHandlerLatency.Observe(dur)
			if dur > 0.05 {
				logrus.WithField("duration", dur).Warn("SPOE handler slow")
			}
			if r := recover(); r != nil {
				logrus.WithField("panic", r).Error("SPOE handler panic")
			}
		}()

		msg, err := req.Messages.GetByName("packet-yeeter-metrics")
		if err != nil {
			return
		}

		var (
			srcIP       net.IP
			clientReqMs int64
		)

		// Helper to extract integers safely
		getInt := func(key string) int64 {
			if val, ok := msg.KV.Get(key); ok {
				switch v := val.(type) {
				case int:
					return int64(v)
				case int64:
					return v
				}
			}
			return 0
		}

		// Helper to extract strings safely
		getString := func(key string) string {
			if val, ok := msg.KV.Get(key); ok {
				if str, ok := val.(string); ok {
					return str
				}
			}
			return ""
		}

		// Parse source IP
		if val, ok := msg.KV.Get("src"); ok {
			if ip, ok := val.(net.IP); ok {
				if ip.To4() == nil && len(ip) == net.IPv6len {
					srcIP = ip
				} else if ip4 := ip.To4(); ip4 != nil {
					srcIP = ip4
				} else {
					srcIP = ip
				}
			}
		}

		tConn := getInt("t_conn")
		tReq := getInt("t_req")

		if tReq > tConn && tConn > 0 {
			clientReqMs = (tReq - tConn) / 1000
		}

		if srcIP == nil {
			return
		}

		// Check AllowList
		if a.checkConfig != nil && a.checkConfig(srcIP) {
			return
		}

		// If queue is backing up, drop fast to avoid SPOE timeouts
		if a.callbacks.QueueLen != nil {
			if ql := a.callbacks.QueueLen(); ql > 9000 {
				metrics.SPOEQueueDrops.Inc()
				return
			}
		}

		// Extract HTTP parameters
		userAgent := getString("ua")
		ja4 := getString("ja4")
		ja4h := getString("ja4h")
		ja4t := getString("ja4t")
		accept := getString("accept")
		acceptLang := getString("accept_language")
		acceptEnc := getString("accept_encoding")
		referer := getString("referer")
		hasCookies := getInt("has_cookies") > 0
		host := getString("host")
		method := getString("method")
		path := getString("path")
		headerOrder := getString("header_order")
		secFetchSite := getString("sec_fetch_site")
		secFetchMode := getString("sec_fetch_mode")
		secFetchDest := getString("sec_fetch_dest")
		secFetchUser := getString("sec_fetch_user")
		tlsVersion := getString("tls_version")
		tlsCipher := getString("tls_cipher")
		connRequestCount := uint32(getInt("conn_request_count"))
		dstPort := uint32(getInt("dst_port"))
		statusCode := uint32(getInt("status"))

		// Extract destination IP
		var dstIP string
		if val, ok := msg.KV.Get("dst"); ok {
			if ip, ok := val.(net.IP); ok {
				dstIP = ip.String()
			}
		}

		// Extract RTT (packet round trip time in microseconds)
		rttUs := getInt("rtt")
		rttMs := float64(rttUs) / 1000.0

		// If eBPF RTT not available, try to correlate with SYN timestamp
		if rttMs == 0 && a.callbacks.GetSynTimestamp != nil {
			if synTime, found := a.callbacks.GetSynTimestamp(srcIP); found {
				// Calculate RTT from SYN to HTTP request
				rttDuration := time.Since(synTime)
				rttMs = float64(rttDuration.Milliseconds())
				logrus.WithFields(logrus.Fields{
					"ip":             srcIP.String(),
					"syn_to_http_ms": rttMs,
					"syn_age":        rttDuration.String(),
				}).Debug("Calculated RTT from eBPF SYN timestamp")
			} else {
				logrus.WithField("ip", srcIP.String()).Debug("No SYN timestamp found for IP")
			}
		}

		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logrus.WithFields(logrus.Fields{
				"src_ip":    srcIP.String(),
				"client_ms": clientReqMs,
				"rtt_us":    rttUs,
				"rtt_ms":    rttMs,
				"t_conn":    tConn,
				"t_req":     tReq,
			}).Debug("SPOE HTTP request")
		}

		// Send comprehensive SPOE signal with all raw data to analyzer
		// The analyzer will perform all lookups, analysis, and decision making
		metadata := map[string]string{}
		if headerOrder != "" {
			metadata["header_order"] = headerOrder
		}

		httpContext := &apiv1.HTTPContext{
			UserAgent:        userAgent,
			Accept:           accept,
			AcceptLanguage:   acceptLang,
			AcceptEncoding:   acceptEnc,
			Referer:          referer,
			HasCookies:       hasCookies,
			Host:             host,
			Method:           method,
			Path:             path,
			ClientReqMs:      clientReqMs,
			PacketRttMs:      rttMs,
			DstPort:          dstPort,
			DstIp:            dstIP,
			StatusCode:       statusCode,
			SecFetchSite:     secFetchSite,
			SecFetchMode:     secFetchMode,
			SecFetchDest:     secFetchDest,
			SecFetchUser:     secFetchUser,
			TlsVersion:       tlsVersion,
			TlsCipher:        tlsCipher,
			ConnRequestCount: connRequestCount,
		}

		a.emitSignal(apiv1.SignalType_SIGNAL_HTTP_REQUEST, srcIP, ja4h, ja4t, ja4, httpContext, metadata)
	}

	// Create SPOP Server
	a.server = agent.New(handler, logger.NewDefaultLog())

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
					serr = err
				}
			}); err != nil {
				return err
			}
			return serr
		},
	}

	var err error
	for i := 0; i < 5; i++ {
		a.listener, err = lc.Listen(context.Background(), "tcp", a.addr)
		if err == nil {
			break
		}
		if errors.Is(err, syscall.EADDRINUSE) {
			logrus.WithError(err).Warn("SPOE listen address in use, retrying...")
			time.Sleep(200 * time.Millisecond)
			continue
		}
		return fmt.Errorf("failed to listen on %s: %w", a.addr, err)
	}
	if err != nil {
		return fmt.Errorf("failed to listen on %s after retries: %w", a.addr, err)
	}

	logrus.WithField("addr", a.addr).Info("Starting Collector SPOE Agent")

	go func() {
		if err := a.server.Serve(a.listener); err != nil {
			select {
			case <-a.stop:
				return
			default:
				logrus.WithError(err).Error("SPOE Server Error")
			}
		}
	}()

	return nil
}

// Stop closes the SPOP listener
func (a *CollectorAgent) Stop() {
	close(a.stop)
	if a.listener != nil {
		a.listener.Close()
	}
}

func (a *CollectorAgent) emitSignal(sigType apiv1.SignalType, ip net.IP, ja4h, ja4t, ja4 string, httpCtx *apiv1.HTTPContext, metadata map[string]string) {
	if a.callbacks.EmitSignal == nil {
		logrus.Warn("EmitSignal callback is nil, cannot send signal")
		return
	}

	sig := &apiv1.Signal{
		Timestamp:   timestamppb.Now(),
		Type:        sigType,
		Source:      apiv1.SignalSource_SOURCE_SPOE,
		Ip:          ip,
		Ja4S:        ja4,
		Ja4H:        ja4h,
		Ja4T:        ja4t,
		HttpContext: httpCtx,
		Asn:         "", // Will be enriched by analyzer
		Org:         "", // Will be enriched by analyzer
		Weight:      1.0,
		Metadata:    metadata,
	}
	if sig.Metadata == nil {
		sig.Metadata = make(map[string]string)
	}
	if ja4 != "" {
		sig.Metadata["ja4"] = ja4
	}
	if ja4h != "" {
		sig.Metadata["ja4h"] = ja4h
	}
	if ja4t != "" {
		sig.Metadata["ja4t"] = ja4t
	}

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logrus.WithFields(logrus.Fields{
			"ip":   ip.String(),
			"type": sigType.String(),
		}).Debug("Emitting SPOE signal to analyzer")
	}

	// EmitSignal -> sendSignal enqueues via a non-blocking select with
	// ring-buffer drop, so calling it inline is already fast; a per-request
	// goroutine here only added scheduler churn and reordered signals.
	a.callbacks.EmitSignal(sig)
}
