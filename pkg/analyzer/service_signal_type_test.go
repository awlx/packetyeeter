package analyzer

import (
	"testing"

	apiv1 "PacketYeeter/api/proto/v1"
)

func TestMapProtoSignalTypeBoundsUnknownValues(t *testing.T) {
	first := mapProtoSignalType(apiv1.SignalType(1000))
	second := mapProtoSignalType(apiv1.SignalType(2000))
	if first != "unknown" || second != "unknown" {
		t.Fatalf("unknown protobuf signal types must share one bounded label, got %q and %q", first, second)
	}
}
