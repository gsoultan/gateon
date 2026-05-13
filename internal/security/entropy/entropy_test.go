package entropy

import (
	"testing"
)

func TestCalculate(t *testing.T) {
	tests := []struct {
		name  string
		input string
		min   float64
		max   float64
	}{
		{"empty", "", 0, 0},
		{"low entropy", "aaaaaaaaaaaaaaaa", 0, 0.1},
		{"high entropy", "r%&^H*()_+J@#$!~", 3.0, 4.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Calculate(tt.input)
			if got < tt.min || got > tt.max {
				t.Errorf("Calculate(%q) = %v, want between %v and %v", tt.input, got, tt.min, tt.max)
			}
		})
	}
}

func TestIsSuspicious(t *testing.T) {
	if IsSuspicious("abc", 4.0) {
		t.Error("expected false for short string")
	}
	if !IsSuspicious("r%&^H*()_+J@#$!~r%&^H*()_+J@#$!~", 3.0) {
		t.Error("expected true for high entropy long string")
	}
}
