package ewma

import (
	"math"
	"time"
)

// State tracks the exponentially weighted moving average
type State struct {
	Value    float64
	LastTime time.Time
}

// Update calculates the EWMA using a time constant (tau)
// Formula: alpha = 1 - exp(-dt/tau), newEWMA = oldEWMA + alpha * (value - oldEWMA)
func Update(prev State, value float64, now time.Time, tau time.Duration) State {
	if prev.LastTime.IsZero() {
		return State{
			Value:    value,
			LastTime: now,
		}
	}

	dt := now.Sub(prev.LastTime)
	if dt <= 0 {
		return prev
	}

	alpha := 1 - math.Exp(-float64(dt)/float64(tau))
	if alpha < 0 {
		alpha = 0
	} else if alpha > 1 {
		alpha = 1
	}

	newValue := prev.Value + alpha*(value-prev.Value)
	return State{
		Value:    newValue,
		LastTime: now,
	}
}

// UpdateWithAlpha calculates the EWMA using a direct alpha value
// Formula: newEWMA = alpha * oldEWMA + (1 - alpha) * value
func UpdateWithAlpha(prev State, value float64, alpha float64, now time.Time) State {
	if prev.LastTime.IsZero() {
		return State{
			Value:    value,
			LastTime: now,
		}
	}

	if alpha < 0 {
		alpha = 0
	} else if alpha > 1 {
		alpha = 1
	}

	newValue := alpha*prev.Value + (1-alpha)*value
	return State{
		Value:    newValue,
		LastTime: now,
	}
}
