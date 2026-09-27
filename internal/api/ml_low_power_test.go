// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"testing"
	"time"
)

// TestMLLowPowerLapsesOnceCPUPressureStopsBeingReported: the resource
// governor's CPU hook is the only caller of SetMLLowPower, it only ever passes
// true, and it fires on every sample above 90%. Low power was a latch, so one
// busy moment -- a burst, a backup on the same host -- cut the isolation
// forest from 100 trees to 25 for the life of the process.
func TestMLLowPowerLapsesOnceCPUPressureStopsBeingReported(t *testing.T) {
	s := &ApiService{}
	s.SetMLLowPower(true)
	now := time.Now()
	if !s.mlLowPowerActive(now) {
		t.Fatal("not in low power right after the governor reported CPU pressure")
	}
	if s.mlLowPowerActive(now.Add(mlLowPowerHold + time.Second)) {
		t.Errorf("still in low power %v after the last CPU pressure report", mlLowPowerHold+time.Second)
	}
}

// TestMLLowPowerHoldsWhilePressureIsReported: the governor samples every five
// seconds; low power must not flap off between two reports of the same spell.
func TestMLLowPowerHoldsWhilePressureIsReported(t *testing.T) {
	s := &ApiService{}
	s.SetMLLowPower(true)
	if !s.mlLowPowerActive(time.Now().Add(5 * time.Second)) {
		t.Error("low power lapsed before the governor's next sample could renew it")
	}
}

func TestMLLowPowerCanBeSwitchedOffAtOnce(t *testing.T) {
	s := &ApiService{}
	s.SetMLLowPower(true)
	s.SetMLLowPower(false)
	if s.mlLowPowerActive(time.Now()) {
		t.Error("SetMLLowPower(false) left the engine in low power")
	}
}
