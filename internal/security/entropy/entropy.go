// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entropy

import (
	"math"
	"sync"
)

var (
	logTable [4097]float64
	logOnce  sync.Once
)

func initLogTable() {
	logOnce.Do(func() {
		for i := 1; i <= 4096; i++ {
			logTable[i] = float64(i) * math.Log2(float64(i))
		}
	})
}

// Calculate computes the Shannon Entropy of a byte slice.
// It returns a value between 0 and 8.
func Calculate(data []byte) float64 {
	n := len(data)
	if n == 0 {
		return 0
	}
	initLogTable()

	var counts [256]int
	for _, b := range data {
		counts[b]++
	}

	total := float64(n)
	var sum float64
	if n <= 4096 {
		for _, count := range counts {
			if count > 0 {
				sum += logTable[count]
			}
		}
	} else {
		for _, count := range counts {
			if count > 0 {
				p := float64(count)
				sum += p * math.Log2(p)
			}
		}
	}

	return math.Log2(total) - (sum / total)
}

// CalculateString computes the Shannon Entropy of a string.
// It is optimized to avoid allocations by iterating over the string bytes directly.
func CalculateString(data string) float64 {
	n := len(data)
	if n == 0 {
		return 0
	}
	initLogTable()

	var counts [256]int
	for i := range n {
		counts[data[i]]++
	}

	total := float64(n)
	var sum float64
	if n <= 4096 {
		for _, count := range counts {
			if count > 0 {
				sum += logTable[count]
			}
		}
	} else {
		for _, count := range counts {
			if count > 0 {
				p := float64(count)
				sum += p * math.Log2(p)
			}
		}
	}

	return math.Log2(total) - (sum / total)
}

// IsSuspicious returns true if the entropy is higher than the threshold.
func IsSuspicious(data string, threshold float64) bool {
	if len(data) < 16 {
		return false
	}
	return CalculateString(data) > threshold
}

// IsSuspiciousBytes returns true if the entropy of the byte slice is higher than the threshold.
func IsSuspiciousBytes(data []byte, threshold float64) bool {
	if len(data) < 16 {
		return false
	}
	return Calculate(data) > threshold
}
