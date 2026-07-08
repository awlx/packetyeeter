package ebpf

// Must match C struct layout
type TcpSessionKey struct {
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
}

type TcpSessionKeyV6 struct {
	Saddr [16]byte
	Daddr [16]byte
	Sport uint16
	Dport uint16
}

type HandshakeStatusGeneric struct {
	BeginTime  uint64
	SynAckTime uint64
	SynAckSent uint8
	Pad        [7]uint8
}

type ICMPRate struct {
	LastTime uint64
	Count    uint64
}

// Bad TCP flag scan classification, matches struct bad_flags_info in
// protector.bpf.c. Values for ScanType match the BAD_FLAGS_* #defines.
const (
	BadFlagsScanNone   = 0
	BadFlagsScanSynFin = 1
	BadFlagsScanXmas   = 2
	BadFlagsScanNull   = 3
)

// BadFlagsScanName returns a human-readable name for a ScanType value.
func BadFlagsScanName(scanType uint32) string {
	switch scanType {
	case BadFlagsScanSynFin:
		return "syn_fin"
	case BadFlagsScanXmas:
		return "xmas"
	case BadFlagsScanNull:
		return "null_scan"
	default:
		return "unknown"
	}
}

type BadFlagsInfo struct {
	LastSeen uint64
	ScanType uint32
	FlagsRaw uint32
}

// EventMetadata matches the C struct event_metadata from protector.bpf.c
type EventMetadata struct {
	SaddrV6        [16]byte
	SaddrV4        uint32
	RttUs          uint32
	Seq            uint32
	TsVal          uint32 // TCP timestamp value
	TsEcr          uint32 // TCP timestamp echo reply
	Sport          uint16
	Dport          uint16
	Window         uint16
	Len            uint16
	Mss            uint16
	Protocol       uint8
	Type           uint8 // 1=JA4T(SYN), 2=RTT(ACK), 3=Connection Pattern
	IsV6           uint8
	TTL            uint8
	TcpFlags       uint8
	Ipv6ExtHeaders uint8
	HasTimestamp   uint8
	EntropyScore   uint8 // 0-100
}
