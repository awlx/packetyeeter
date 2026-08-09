package analyzer

import (
	"sync/atomic"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/metrics"

	"github.com/sirupsen/logrus"
)

// enforcementState is the analyzer's runtime enforcement kill switch.
//
// It sits at the point commands are issued rather than inside any one detector,
// because the situation it exists for - "we are blocking traffic we should not
// be, right now" - is never known to be confined to a single detector, and an
// operator in that situation should not have to work out which one is
// responsible before they can stop it.
//
// It complements -dry-run rather than duplicating it: -dry-run is a deployment
// decision fixed at startup, this is an incident response reachable in seconds
// over the inspector.
//
// It is deliberately one-way. Turning enforcement off has to be immediate;
// turning it back on should go through a config change and a restart, which
// leaves a record of the decision. It is not persisted, so a restart returns to
// whatever the deployed configuration says.
type enforcementState struct {
	stopped atomic.Bool
	reason  atomic.Value // string
}

// Stop halts all enforcing commands. Detection, scoring, metrics, and the
// reporting surfaces keep running, so the analyzer continues to show what it
// would have blocked.
func (e *enforcementState) Stop(reason string) {
	if reason == "" {
		reason = "no reason given"
	}
	e.reason.Store(reason)
	e.stopped.Store(true)
	metrics.EnforcementStopped.Set(1)
}

// Status reports whether enforcement has been stopped, and why.
func (e *enforcementState) Status() (bool, string) {
	if !e.stopped.Load() {
		return false, ""
	}
	reason, _ := e.reason.Load().(string)
	return true, reason
}

// EnforcementStopped reports whether the runtime kill switch has been pulled.
func (a *Analyzer) EnforcementStopped() (bool, string) {
	return a.enforcement.Status()
}

// StopEnforcement pulls the runtime kill switch.
func (a *Analyzer) StopEnforcement(reason string) {
	a.enforcement.Stop(reason)
	logrus.WithField("reason", reason).
		Warn("Enforcement stopped at runtime; all BLOCK commands suppressed. Detection continues. Re-enabling requires a restart.")
}

// Enforcing reports whether the analyzer currently issues enforcing commands.
func (a *Analyzer) Enforcing() bool {
	stopped, _ := a.enforcement.Status()
	return !a.Config.DryRun && !stopped
}

// isEnforcingCommand reports whether a command restricts traffic.
//
// Relieving commands - unblocks and allowlist additions - are deliberately
// excluded. The kill switch is pulled precisely when something is being blocked
// that should not be, so suppressing the commands that undo a block would make
// it worse rather than better.
func isEnforcingCommand(cmd *apiv1.Command) bool {
	switch cmd.GetType() {
	case apiv1.CommandType_COMMAND_BLOCK_IP, apiv1.CommandType_COMMAND_BLOCK_CIDR:
		return true
	default:
		return false
	}
}

// suppressedByKillSwitch reports whether a command must not be issued because
// enforcement has been stopped at runtime.
func (a *Analyzer) suppressedByKillSwitch(cmd *apiv1.Command) bool {
	if !isEnforcingCommand(cmd) {
		return false
	}
	stopped, reason := a.enforcement.Status()
	if !stopped {
		return false
	}
	metrics.EnforcementSuppressedCommands.Inc()
	logrus.WithFields(logrus.Fields{
		"cmd":    cmd.String(),
		"reason": reason,
	}).Warn("Enforcement stopped: suppressing block command")
	return true
}
