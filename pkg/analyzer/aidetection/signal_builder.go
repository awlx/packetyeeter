package aidetection

import (
	"net"
	"time"
)

// SignalBuilder provides a convenient API for emitting signals with reduced boilerplate
type SignalBuilder struct {
	engine *Engine
}

// NewSignalBuilder creates a new signal builder
func NewSignalBuilder(engine *Engine) *SignalBuilder {
	return &SignalBuilder{engine: engine}
}

// Emit emits a signal if the engine is available
func (b *SignalBuilder) Emit(signal Signal) {
	if b.engine == nil {
		return
	}
	if signal.Timestamp.IsZero() {
		signal.Timestamp = time.Now()
	}
	b.engine.EmitSignal(signal)
}

// EmitBotUA emits a bot user agent signal
func (b *SignalBuilder) EmitBotUA(ip net.IP, asn, org, userAgent string, weight float64, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["user_agent"] = userAgent

	b.Emit(Signal{
		IP:       ip,
		Type:     SignalBotUA,
		Source:   SourceSPOE,
		ASN:      asn,
		Org:      org,
		Weight:   weight,
		Metadata: metadata,
	})
}

// EmitMissingHeader emits a signal for missing HTTP headers
func (b *SignalBuilder) EmitMissingHeader(ip net.IP, asn, org string, signalType SignalType, userAgent string, weight float64, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["user_agent"] = userAgent

	b.Emit(Signal{
		IP:       ip,
		Type:     signalType,
		Source:   SourceSPOE,
		ASN:      asn,
		Org:      org,
		Weight:   weight,
		Metadata: metadata,
	})
}

// EmitTimingRegularity emits a signal for metronomic (low-variance)
// inter-request timing, indicating scripted polling/crawling rather than
// human browsing.
func (b *SignalBuilder) EmitTimingRegularity(ip net.IP, asn, org, userAgent string, weight float64, sampleCount int) {
	b.Emit(Signal{
		IP:     ip,
		Type:   SignalRequestTimingRegular,
		Source: SourceSPOE,
		ASN:    asn,
		Org:    org,
		Weight: weight,
		Metadata: map[string]interface{}{
			"user_agent":   userAgent,
			"sample_count": sampleCount,
		},
	})
}

// EmitJA4Rotation emits a signal when an IP presents multiple distinct
// JA4/JA4H fingerprints while claiming a consistent browser identity.
func (b *SignalBuilder) EmitJA4Rotation(ip net.IP, asn, org, userAgent string, weight float64, ja4Count, ja4hCount int) {
	b.Emit(Signal{
		IP:     ip,
		Type:   SignalJA4Rotation,
		Source: SourceSPOE,
		ASN:    asn,
		Org:    org,
		Weight: weight,
		Metadata: map[string]interface{}{
			"user_agent": userAgent,
			"ja4_count":  ja4Count,
			"ja4h_count": ja4hCount,
		},
	})
}

// EmitProxyLag emits a proxy lag anomaly signal
func (b *SignalBuilder) EmitProxyLag(ip net.IP, asn, org string, proxyLagMs, rttMs, ewma, threshold float64, userAgent string) {
	b.Emit(Signal{
		IP:     ip,
		Type:   SignalProxyLag,
		Source: SourceSPOE,
		ASN:    asn,
		Org:    org,
		Weight: 1.0,
		Metadata: map[string]interface{}{
			"proxy_lag_ms": proxyLagMs,
			"rtt_ms":       rttMs,
			"user_agent":   userAgent,
			"ewma":         ewma,
			"threshold":    threshold,
		},
	})
}

// EmitLatencyAnomaly emits a latency anomaly signal
func (b *SignalBuilder) EmitLatencyAnomaly(ip net.IP, asn, org string, proxyLagMs, rttMs, ewma, threshold float64) {
	b.Emit(Signal{
		IP:     ip,
		Type:   SignalLatencyAnomaly,
		Source: SourceSPOE,
		ASN:    asn,
		Org:    org,
		Weight: 1.0,
		Metadata: map[string]interface{}{
			"proxy_lag_ms": proxyLagMs,
			"rtt_ms":       rttMs,
			"ewma":         ewma,
			"threshold":    threshold,
		},
	})
}

// EmitPathEntropy emits path entropy signals
func (b *SignalBuilder) EmitPathEntropy(ip net.IP, asn, org, path string, entropy float64, unique, total int) {
	b.Emit(Signal{
		IP:     ip,
		Type:   SignalPathEntropyLow,
		Source: SourceSPOE,
		ASN:    asn,
		Org:    org,
		Weight: 1.5,
		Metadata: map[string]interface{}{
			"entropy": entropy,
			"path":    path,
			"unique":  unique,
			"total":   total,
		},
	})
}

// EmitSequentialPath emits sequential path ID signals
func (b *SignalBuilder) EmitSequentialPath(ip net.IP, asn, org, path string, signalType SignalType, weight float64) {
	b.Emit(Signal{
		IP:     ip,
		Type:   signalType,
		Source: SourceSPOE,
		ASN:    asn,
		Org:    org,
		Weight: weight,
		Metadata: map[string]interface{}{
			"path": path,
		},
	})
}

// EmitHTTPErrorSignal emits signals for excessive HTTP errors (404, 403) indicating scanners
func (b *SignalBuilder) EmitHTTPErrorSignal(ip net.IP, asn, org string, signalType SignalType, weight float64, count404, count403, consecutive int) {
	b.Emit(Signal{
		IP:     ip,
		Type:   signalType,
		Source: SourceSPOE,
		ASN:    asn,
		Org:    org,
		Weight: weight,
		Metadata: map[string]interface{}{
			"404_count":         count404,
			"403_count":         count403,
			"consecutive_error": consecutive,
		},
	})
}

// EmitJA4Match emits a JA4 fingerprint match signal
func (b *SignalBuilder) EmitJA4Match(ip net.IP, asn, org, ja4, ja4h, ja4t string, signalType SignalType, weight float64, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	b.Emit(Signal{
		IP:       ip,
		Type:     signalType,
		Source:   SourceFingerprint,
		JA4:      ja4,
		JA4H:     ja4h,
		JA4T:     ja4t,
		ASN:      asn,
		Org:      org,
		Weight:   weight,
		Metadata: metadata,
	})
}

// EmitHeaderAnomaly emits header-related anomaly signals
func (b *SignalBuilder) EmitHeaderAnomaly(ip net.IP, asn, org string, signalType SignalType, ja4, ja4h, ja4t string, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	b.Emit(Signal{
		IP:       ip,
		Type:     signalType,
		Source:   SourceSPOE,
		JA4:      ja4,
		JA4H:     ja4h,
		JA4T:     ja4t,
		ASN:      asn,
		Org:      org,
		Weight:   2.0,
		Metadata: metadata,
	})
}

// EmitThreatIntel emits threat intelligence signals
func (b *SignalBuilder) EmitThreatIntel(ip net.IP, asn, org string, signalType SignalType, weight float64, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	b.Emit(Signal{
		IP:       ip,
		Type:     signalType,
		Source:   SourceSPOE,
		ASN:      asn,
		Org:      org,
		Weight:   weight,
		Metadata: metadata,
	})
}

// EmitKnownScanner emits a known scanner detection signal
func (b *SignalBuilder) EmitKnownScanner(ip net.IP, asn, org string, threatScore float64, tags, sources []string) {
	b.Emit(Signal{
		IP:     ip,
		Type:   SignalKnownScanner,
		Source: SourceSPOE,
		ASN:    asn,
		Org:    org,
		Weight: 50.0,
		Metadata: map[string]interface{}{
			"threat_score":     threatScore,
			"is_known_scanner": true,
			"tags":             tags,
			"sources":          sources,
		},
	})
}
