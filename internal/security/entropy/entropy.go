package entropy

import (
	"math"
)

// Calculate computes the Shannon Entropy of a byte slice.
// It returns a value between 0 and 8.
func Calculate(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var counts [256]int
	for _, b := range data {
		counts[b]++
	}

	total := float64(len(data))
	var entropy float64
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// CalculateString computes the Shannon Entropy of a string.
// It is optimized to avoid allocations by iterating over the string bytes directly.
func CalculateString(data string) float64 {
	if len(data) == 0 {
		return 0
	}

	var counts [256]int
	for i := range len(data) {
		counts[data[i]]++
	}

	total := float64(len(data))
	var entropy float64
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
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
