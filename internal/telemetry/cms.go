package telemetry

import (
	"sync/atomic"
)

// CMSketch implements a Count-Min Sketch for memory-efficient frequency estimation.
// It is used for global rate limiting and identifying Top-K attackers with constant memory.
type CMSketch struct {
	width  int
	depth  int
	counts [][]uint32
}

// NewCMSketch creates a new Count-Min Sketch.
// width determines the accuracy, depth determines the probability of error.
func NewCMSketch(width, depth int) *CMSketch {
	counts := make([][]uint32, depth)
	for i := range depth {
		counts[i] = make([]uint32, width)
	}
	return &CMSketch{
		width:  width,
		depth:  depth,
		counts: counts,
	}
}

// Add increments the count for the given key by 1.
func (c *CMSketch) Add(key string) {
	c.AddWeighted(key, 1)
}

// AddWeighted increments the count for the given key by the specified value.
// It is optimized to be lock-free using atomic increments and a fast hash function.
func (c *CMSketch) AddWeighted(key string, count uint32) {
	for i := range c.depth {
		h := c.fastHash(key, uint64(i))
		idx := int(h % uint64(c.width))
		atomic.AddUint32(&c.counts[i][idx], count)
	}
}

// Estimate returns the estimated frequency of the key.
func (c *CMSketch) Estimate(key string) uint32 {
	var minVal uint32 = 0xFFFFFFFF
	for i := range c.depth {
		h := c.fastHash(key, uint64(i))
		idx := int(h % uint64(c.width))
		val := atomic.LoadUint32(&c.counts[i][idx])
		if val < minVal {
			minVal = val
		}
	}
	return minVal
}

// fastHash is a fast, non-cryptographic hash function (FNV-1a like).
func (c *CMSketch) fastHash(key string, seed uint64) uint64 {
	h := uint64(14695981039346656037) ^ seed
	for i := range len(key) {
		h ^= uint64(key[i])
		h *= 1099511628211
	}
	return h
}

// Clear resets the sketch.
func (c *CMSketch) Clear() {
	for i := range c.depth {
		for j := range c.width {
			atomic.StoreUint32(&c.counts[i][j], 0)
		}
	}
}
