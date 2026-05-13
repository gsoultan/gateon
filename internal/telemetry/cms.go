package telemetry

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
)

// CMSketch implements a Count-Min Sketch for memory-efficient frequency estimation.
// It is used for global rate limiting and identifying Top-K attackers with constant memory.
type CMSketch struct {
	mu     sync.RWMutex
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

// Add increments the count for the given key.
func (c *CMSketch) Add(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	data := []byte(key)
	for i := range c.depth {
		hash := c.hash(data, i)
		idx := int(hash % uint64(c.width))
		c.counts[i][idx]++
	}
}

// Estimate returns the estimated frequency of the key.
func (c *CMSketch) Estimate(key string) uint32 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	data := []byte(key)
	var min uint32 = 0xFFFFFFFF
	for i := range c.depth {
		hash := c.hash(data, i)
		idx := int(hash % uint64(c.width))
		count := c.counts[i][idx]
		if count < min {
			min = count
		}
	}
	return min
}

func (c *CMSketch) hash(data []byte, seed int) uint64 {
	h := sha256.New()
	binary.Write(h, binary.LittleEndian, uint32(seed))
	h.Write(data)
	sum := h.Sum(nil)
	return binary.LittleEndian.Uint64(sum[:8])
}

// Clear resets the sketch.
func (c *CMSketch) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.depth {
		for j := range c.width {
			c.counts[i][j] = 0
		}
	}
}
