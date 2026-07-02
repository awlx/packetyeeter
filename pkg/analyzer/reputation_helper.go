package analyzer

import (
	"net"

	"PacketYeeter/pkg/analyzer/reputation"
)

// ReputationHelper provides a convenient wrapper for reputation operations with nil-safety
type ReputationHelper struct {
	engine *reputation.Engine
}

// NewReputationHelper creates a new reputation helper
func NewReputationHelper(engine *reputation.Engine) *ReputationHelper {
	return &ReputationHelper{engine: engine}
}

// PenalizeIP penalizes an IP address if reputation engine is available
func (h *ReputationHelper) PenalizeIP(ip net.IP, weight float64, reason string) {
	if h.engine == nil || ip == nil {
		return
	}
	h.engine.Penalize(ip.String(), reputation.TypeIP, weight, reason)
}

// PenalizeASN penalizes an ASN if reputation engine is available
func (h *ReputationHelper) PenalizeASN(asn string, ip net.IP, weight float64, reason string) {
	if h.engine == nil || asn == "" || asn == "Unknown" || ip == nil {
		return
	}
	h.engine.ObserveIP(asn, ip.String())
	h.engine.PenalizeASN(asn, ip.String(), weight, reason)
}

// PenalizeJA4 penalizes a JA4 fingerprint if reputation engine is available
func (h *ReputationHelper) PenalizeJA4(ja4 string, weight float64, reason string) {
	if h.engine == nil || ja4 == "" {
		return
	}
	h.engine.Penalize(ja4, reputation.TypeJA4, weight, reason)
}

// RewardIP rewards an IP address for good behavior
func (h *ReputationHelper) RewardIP(ip net.IP, weight float64, reason string) {
	if h.engine == nil || ip == nil {
		return
	}
	h.engine.RewardIP(ip.String(), weight, reason)
}

// RewardJA4 rewards a JA4 fingerprint for good behavior
func (h *ReputationHelper) RewardJA4(ja4 string, weight float64, reason string) {
	if h.engine == nil || ja4 == "" {
		return
	}
	h.engine.RewardJA4(ja4, weight, reason)
}

// RewardASN rewards an ASN for good behavior
func (h *ReputationHelper) RewardASN(asn string, ip net.IP, weight float64, reason string) {
	if h.engine == nil || asn == "" || asn == "Unknown" || ip == nil {
		return
	}
	h.engine.RewardASN(asn, ip.String(), weight, reason)
}

// RewardBrowser rewards IP, JA4, and ASN for verified browser behavior
func (h *ReputationHelper) RewardBrowser(ip net.IP, ja4, asn string) {
	h.RewardIP(ip, 5.0, "browser_exact_ja4")
	if ja4 != "" {
		h.RewardJA4(ja4, 5.0, "browser_exact_ja4")
	}
	if asn != "" && asn != "Unknown" {
		h.RewardASN(asn, ip, 1.0, "browser_exact_ja4")
	}
}

// GetScore retrieves the reputation score for an entity
func (h *ReputationHelper) GetScore(key string, entityType reputation.EntityType) float64 {
	if h.engine == nil {
		return 0
	}
	return h.engine.GetScore(key, entityType)
}

// ObserveIP records an IP as active in an ASN
func (h *ReputationHelper) ObserveIP(asn string, ip net.IP) {
	if h.engine == nil || asn == "" || asn == "Unknown" || ip == nil {
		return
	}
	h.engine.ObserveIP(asn, ip.String())
}
