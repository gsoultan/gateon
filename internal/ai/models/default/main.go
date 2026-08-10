// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

//lint:ignore U1000 inputBuf is used by WASM exported functions
var inputBuf [1024]float64

// get_input_ptr returns the pointer to the input buffer.
//
//go:wasmexport get_input_ptr
//lint:ignore U1000 exported to WASM host
func get_input_ptr() *float64 {
	return &inputBuf[0]
}

//lint:ignore U1000 internal helper for exp
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

//lint:ignore U1000 internal helper for predict
func exp(x float64) float64 {
	// Simple approximation of exp(x) for sigmoid
	// e^x = (1 + x/n)^n for large n. Let's use n=256
	x = 1.0 + x/256.0
	x *= x // 2
	x *= x // 4
	x *= x // 8
	x *= x // 16
	x *= x // 32
	x *= x // 64
	x *= x // 128
	x *= x // 256
	return x
}

// predict performs a double exponential smoothing (Holt's Linear Trend) to predict traffic spikes.
// This is more accurate than simple moving averages as it captures trends.
//
//go:wasmexport predict
//lint:ignore U1000 exported to WASM host
func predict(length uint32) float64 {
	if length < 2 {
		return 0
	}
	if length > 1024 {
		length = 1024
	}

	input := inputBuf[:length]

	// Holt's Linear Trend parameters
	alpha := 0.5 // Level smoothing
	beta := 0.3  // Trend smoothing

	level := input[0]
	trend := input[1] - input[0]

	// Process all but the last value to establish trend
	for i := uint32(1); i < length-1; i++ {
		lastLevel := level
		level = alpha*input[i] + (1-alpha)*(level+trend)
		trend = beta*(level-lastLevel) + (1-beta)*trend
	}

	// Forecast next value (the last one)
	forecast := level + trend

	// Current value
	latest := input[length-1]

	// Calculate anomaly score based on forecast deviation
	diff := latest - forecast
	if diff <= 0 {
		return 0
	}

	// Normalize score: how many times it exceeded the trend
	score := diff / (abs(level) + 1.0)

	// Normalize to 0-1 range using sigmoid approximation
	// centered around significant deviation
	val := (score - 1.5) * 2.0
	return 1.0 / (1.0 + 1.0/exp(val))
}

func main() {}
