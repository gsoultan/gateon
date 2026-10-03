// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// WeightedRoundRobinLB is round robin by weight. Since round robin honours
// weights itself (ADR 0047) the two policies are one balancer; both names stay
// because services are saved under both.
type WeightedRoundRobinLB = RoundRobinLB

func NewWeightedRoundRobinLB(targets []*gateonv1.Target) *WeightedRoundRobinLB {
	lb := &RoundRobinLB{}
	lb.UpdateWeightedTargets(targets)
	return lb
}

// maxScheduleLen bounds the smooth schedule a balancer keeps: 4096 entries of
// four bytes, 16 KiB, for a route whose weights (divided by their common
// factor) add up to that much. Larger sums keep exact proportions without the
// interleaving (rrSet.pickLive walks the weights instead).
const maxScheduleLen = 4096

// effectiveShares is what each target is owed. A service saved with no weight
// on any target (proto3's zero) means "no preference", so every target gets 1.
// Once any target carries a weight, a target at zero is on standby and gets
// nothing: that is how a canary is held at 0%.
func effectiveShares(targets []*gateonv1.Target) []int32 {
	shares := make([]int32, len(targets))
	weighted := false
	for i, t := range targets {
		if t != nil && t.Weight > 0 {
			shares[i] = t.Weight
			weighted = true
		}
	}
	if !weighted {
		for i := range shares {
			shares[i] = 1
		}
	}
	return shares
}

// smoothSchedule is the order smooth weighted round robin (nginx's) serves the
// shares in: each target appears share/gcd times per cycle, spread out, so
// weights 6:1:1 go a a b a a c a a rather than six in a row to one backend
// (whole 40-request bursts went to one canary target at 50/50). Equal shares
// give plain rotation. Nil when the cycle would exceed maxScheduleLen.
func smoothSchedule(shares []int32) []uint32 {
	g := int64(0)
	for _, s := range shares {
		if s > 0 {
			g = gcd(g, int64(s))
		}
	}
	if g == 0 {
		return nil
	}
	reduced := make([]int64, len(shares))
	total := int64(0)
	for i, s := range shares {
		if s > 0 {
			reduced[i] = int64(s) / g
			total += reduced[i]
		}
	}
	if total > maxScheduleLen {
		return nil
	}
	return interleave(reduced, total)
}

// interleave runs one cycle of smooth weighted round robin: every turn each
// target gains its weight, the richest is picked and pays the total.
func interleave(weights []int64, total int64) []uint32 {
	order := make([]uint32, 0, total)
	current := make([]int64, len(weights))
	for range total {
		best := -1
		for i, w := range weights {
			if w <= 0 {
				continue
			}
			current[i] += w
			if best < 0 || current[i] > current[best] {
				best = i
			}
		}
		current[best] -= total
		order = append(order, uint32(best)) //nolint:gosec // best < len(weights), an int32-sized target count
	}
	return order
}

func gcd(a, b int64) int64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}
