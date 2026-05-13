package telemetry

import (
	"math"
	"sync"
)

// ZScoreCalculator implements Statistical Process Control using Z-Scores.
// It detects anomalies by measuring how many standard deviations a value is from the mean.
type ZScoreCalculator struct {
	mu    sync.RWMutex
	sum   float64
	sumSq float64
	n     int
}

// Add adds a new observation to the calculator.
func (c *ZScoreCalculator) Add(val float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sum += val
	c.sumSq += val * val
	c.n++
}

// GetZScore returns the Z-Score of the given value based on current observations.
func (c *ZScoreCalculator) GetZScore(val float64) float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.n < 2 {
		return 0
	}
	mean := c.sum / float64(c.n)
	variance := (c.sumSq / float64(c.n)) - (mean * mean)
	if variance <= 0 {
		return 0
	}
	stdDev := math.Sqrt(variance)
	return (val - mean) / stdDev
}

// EWMACalculator implements Exponentially Weighted Moving Average.
// It is useful for detecting sudden spikes in real-time streams.
type EWMACalculator struct {
	mu    sync.RWMutex
	value float64
	alpha float64 // Smoothing factor (0 < alpha < 1)
}

// NewEWMA creates a new EWMA calculator with the given alpha.
func NewEWMA(alpha float64) *EWMACalculator {
	return &EWMACalculator{
		alpha: alpha,
	}
}

// Add updates the EWMA with a new value.
func (c *EWMACalculator) Add(val float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.value == 0 {
		c.value = val
	} else {
		c.value = c.alpha*val + (1-c.alpha)*c.value
	}
}

// Value returns the current EWMA value.
func (c *EWMACalculator) Value() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.value
}
