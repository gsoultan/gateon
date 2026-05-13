package entropy

import (
	"math"
)

// Calculate computes the Shannon Entropy of a string.
// It returns a value between 0 and 8 (for byte-based entropy).
// High entropy (> 4.5-5.0) in fields that should be plain text can indicate
// encrypted payloads, shellcode, or packed malware.
func Calculate(data string) float64 {
	if len(data) == 0 {
		return 0
	}

	// Use a fixed size array for better performance with ASCII/UTF-8 bytes
	var counts [256]int
	for i := range len(data) {
		counts[data[i]]++
	}
	total := len(data)

	var entropy float64
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// IsSuspicious returns true if the entropy is higher than the threshold.
func IsSuspicious(data string, threshold float64) bool {
	if len(data) < 16 { // Too small to be statistically significant for entropy
		return false
	}
	return Calculate(data) > threshold
}
