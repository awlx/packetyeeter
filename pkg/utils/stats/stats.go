package stats

import (
	"math"
	"time"
)

// Package stats provides statistical helper functions.
//
// Two approaches are provided:
//
// 1. Online/Streaming Statistics (Welford's Algorithm):
//    - Use when: Processing data points one at a time as they arrive
//    - Advantages: O(1) memory, numerically stable, single-pass
//    - Examples: ASN baseline calibration, real-time metrics
//    - Functions: UpdateRunningStats, NewRunningStats
//
// 2. Post-Hoc Batch Statistics:
//    - Use when: Analyzing a complete dataset that's already collected
//    - Advantages: Simpler to understand, useful for sliding windows
//    - Examples: Pattern analysis over buffered observations
//    - Functions: CalculateMean, CalculateStdDev, CalculateVariance

// RunningStats tracks mean and variance using Welford's online algorithm.
// This is ideal for streaming data where you process one observation at a time
// and want to maintain running statistics without storing all observations.
//
// Welford's algorithm is numerically stable and requires O(1) memory regardless
// of the number of observations.
type RunningStats struct {
	Count    uint64
	Mean     float64
	M2       float64 // Sum of squared differences from mean
	Min      float64
	Max      float64
	LastSeen time.Time
}

// NewRunningStats creates a new RunningStats instance
func NewRunningStats() *RunningStats {
	return &RunningStats{}
}

// UpdateRunningStats updates running statistics using Welford's online algorithm.
// This is an O(1) operation that maintains numerical stability.
//
// Algorithm:
//  1. delta = value - mean
//  2. mean = mean + delta / count
//  3. delta2 = value - mean
//  4. M2 = M2 + delta * delta2
//
// Variance can then be computed as: M2 / (count - 1)
func UpdateRunningStats(stats *RunningStats, value float64, timestamp time.Time) {
	stats.Count++
	delta := value - stats.Mean
	stats.Mean += delta / float64(stats.Count)
	delta2 := value - stats.Mean
	stats.M2 += delta * delta2

	if stats.Count == 1 {
		stats.Min = value
		stats.Max = value
	} else {
		if value < stats.Min {
			stats.Min = value
		}
		if value > stats.Max {
			stats.Max = value
		}
	}

	stats.LastSeen = timestamp
}

// Variance returns the sample variance (M2 / (n-1))
func (s *RunningStats) Variance() float64 {
	if s.Count < 2 {
		return 0
	}
	return s.M2 / float64(s.Count-1)
}

// StdDev returns the sample standard deviation
func (s *RunningStats) StdDev() float64 {
	return math.Sqrt(s.Variance())
}

// ZScore calculates the z-score for a value against these running statistics
func (s *RunningStats) ZScore(value float64) float64 {
	if s.Count < 2 {
		return 0
	}

	stdDev := s.StdDev()
	if stdDev < 1e-9 {
		return 0 // Avoid division by zero
	}

	return (value - s.Mean) / stdDev
}

// CalculateMean calculates the arithmetic mean of a slice of float64 values.
// Use this for post-hoc analysis of collected data (e.g., buffered observations).
func CalculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// CalculateMeanDuration calculates the arithmetic mean of a slice of time.Duration values.
// Use this for analyzing timing patterns over a sliding window.
func CalculateMeanDuration(timings []time.Duration) time.Duration {
	if len(timings) == 0 {
		return 0
	}

	var sum int64
	for _, t := range timings {
		sum += t.Milliseconds()
	}

	return time.Duration(sum/int64(len(timings))) * time.Millisecond
}

// CalculateVariance calculates the sample variance of a slice of float64 values.
// Use this for post-hoc analysis of collected data.
func CalculateVariance(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}

	mean := CalculateMean(values)

	var sumSquares float64
	for _, v := range values {
		diff := v - mean
		sumSquares += diff * diff
	}

	return sumSquares / float64(len(values)-1)
}

// CalculateStdDev calculates the sample standard deviation of a slice of float64 values.
// Use this for post-hoc analysis of collected data (e.g., calculating coefficient of variation).
func CalculateStdDev(values []float64) float64 {
	return math.Sqrt(CalculateVariance(values))
}

// CalculateStdDevDuration calculates the sample standard deviation of time.Duration values.
// Useful for detecting mechanical timing patterns (low stddev = scripted behavior).
func CalculateStdDevDuration(timings []time.Duration) float64 {
	if len(timings) < 2 {
		return 0
	}

	mean := CalculateMeanDuration(timings).Milliseconds()

	var sumSquares float64
	for _, t := range timings {
		diff := float64(t.Milliseconds() - mean)
		sumSquares += diff * diff
	}

	variance := sumSquares / float64(len(timings)-1)
	return math.Sqrt(variance)
}

// CoefficientOfVariation calculates the coefficient of variation (CV = stddev / mean).
// CV is useful for detecting mechanical/scripted behavior:
//   - CV < 0.05: Highly mechanical (bot-like)
//   - CV < 0.1: Somewhat regular (scripted or automated)
//   - CV > 0.3: Natural variation (likely human)
func CoefficientOfVariation(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}

	mean := CalculateMean(values)
	if mean == 0 {
		return 0
	}

	stdDev := CalculateStdDev(values)
	return stdDev / mean
}
