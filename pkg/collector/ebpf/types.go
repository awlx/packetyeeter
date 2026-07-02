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
