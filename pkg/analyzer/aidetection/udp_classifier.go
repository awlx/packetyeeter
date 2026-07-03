package aidetection

import (
	"fmt"
	"strings"
)

func classifyUDPAttackVector(signal Signal) SignalType {
	if !isUDPSignal(signal) {
		return signal.Type
	}
	if !metadataAllowsUDP(signal.Metadata) {
		return SignalUDPFlood
	}

	if isQUICInitial(signal.Metadata) {
		return SignalQUICInitialFlood
	}
	if metadataIndicates(signal.Metadata, "dns", "dns_qtype", "dns_opcode", "dns_rcode") || hasUDPPort(signal.Metadata, 53) {
		return SignalDNSReflection
	}
	if metadataIndicates(signal.Metadata, "ntp", "ntp_mode", "ntp_version") || hasUDPPort(signal.Metadata, 123) {
		return SignalNTPReflection
	}
	if metadataIndicates(signal.Metadata, "ssdp", "ssdp_st", "ssdp_usn") || metadataContains(signal.Metadata, "m-search") || hasUDPPort(signal.Metadata, 1900) {
		return SignalSSDPReflection
	}
	if metadataIndicates(signal.Metadata, "cldap", "ldap") || hasUDPPort(signal.Metadata, 389) {
		return SignalCLDAPReflection
	}
	if metadataIndicates(signal.Metadata, "memcached") || hasUDPPort(signal.Metadata, 11211) {
		return SignalMemcachedReflection
	}

	return SignalUDPFlood
}

func isUDPSignal(signal Signal) bool {
	if signal.Source == SourceUDP || signal.Type == SignalUDPFlood {
		return true
	}
	transport := transportProtocol(signal.Metadata)
	return transport == "udp" || transport == "17"
}

func metadataAllowsUDP(metadata map[string]interface{}) bool {
	transport := transportProtocol(metadata)
	return transport == "" || transport == "udp" || transport == "17"
}

func transportProtocol(metadata map[string]interface{}) string {
	transport := strings.ToLower(metadataString(metadata, "transport", "ip_protocol", "l4_protocol"))
	if transport != "" {
		return transport
	}
	protocol := strings.ToLower(metadataString(metadata, "protocol"))
	switch protocol {
	case "udp", "tcp", "17", "6":
		return protocol
	default:
		return ""
	}
}

func isQUICInitial(metadata map[string]interface{}) bool {
	if metadata == nil || !hasUDPPort(metadata, 443) {
		return false
	}
	if metadataIndicates(metadata, "quic", "quic_version", "quic_dcid", "quic_scid", "quic_cid", "quic_packet_type") {
		return true
	}
	packetType := strings.ToLower(metadataString(metadata, "packet_type", "quic_packet_type"))
	return strings.Contains(packetType, "initial")
}

func metadataIndicates(metadata map[string]interface{}, protocol string, keys ...string) bool {
	if metadata == nil {
		return false
	}
	for _, key := range keys {
		if _, ok := metadata[key]; ok {
			return true
		}
	}
	for _, key := range []string{"app_protocol", "application_protocol", "protocol", "payload_protocol", "service"} {
		if strings.EqualFold(metadataString(metadata, key), protocol) {
			return true
		}
	}
	return false
}

func hasUDPPort(metadata map[string]interface{}, want uint32) bool {
	if metadata == nil {
		return false
	}
	for _, key := range []string{
		"dst_port", "dest_port", "destination_port",
		"src_port", "source_port",
		"service_port", "port",
	} {
		if v, ok := metadata[key]; ok {
			if port, ok := uint32FromValue(v); ok && port == want {
				return true
			}
		}
	}
	return false
}

func metadataContains(metadata map[string]interface{}, needle string) bool {
	if metadata == nil {
		return false
	}
	needle = strings.ToLower(needle)
	for _, key := range []string{"payload", "payload_sample", "payload_prefix", "request_line", "method"} {
		if strings.Contains(strings.ToLower(metadataValueString(metadata[key])), needle) {
			return true
		}
	}
	return false
}

func metadataValueString(v interface{}) string {
	switch typed := v.(type) {
	case nil:
		return ""
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	case []byte:
		return string(typed)
	default:
		return fmt.Sprint(typed)
	}
}
