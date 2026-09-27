// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/e-XpertSolutions/go-iforest/v2/iforest"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// NeuralAnomalyDetector -- the "Neural Sentinel" -- is an isolation forest
// (go-iforest) over what each client did in the analysis window. Nothing about
// it is neural; the name is kept because it is the one the dashboard shows.
//
// It reports a client when both hold:
//
//   - the forest isolates it from the rest of the population far more easily
//     than a typical member: an absolute score, compared against a fixed bar
//     the operator's Sensitivity moves (neuralThreshold). Not the library's
//     labels, which mark a fixed fraction (its "anomaly ratio") of any
//     population, however ordinary, as anomalous;
//   - its traffic is harmful (IPStats.harmEvidence). Unusual is not harmful: a
//     CI runner, an office's egress or a status poller is an outlier among
//     browsers, and the forest rightly says so.
//
// Its findings can end in a kernel throttle, through the RL limiter's
// repeated-evidence rule, so both halves are sized for false positives first.
type NeuralAnomalyDetector struct {
	Config   *gateonv1.AnomalyDetectionConfig
	LowPower int32 // atomic: 0 = normal, 1 = low power
}

const (
	neuralSentinelType = "neural_sentinel"

	// neuralMinRequests is how many traced requests a client needs before its
	// behaviour is measured at all.
	neuralMinRequests = 5
	// neuralMinPopulation is the smallest population an outlier is judged
	// against: below it, "unlike the others" means unlike a handful.
	neuralMinPopulation = 20

	// The forest: the library's own defaults for tree count and subsample
	// ceiling. The anomaly ratio only positions the library's labels, which
	// nothing reads.
	neuralTrees        = 100
	neuralMaxSubsample = 256
	neuralAnomalyRatio = 0.05

	// neuralThreshold maps the dashboard's Sensitivity (0..1, default 0.5)
	// onto the standard isolation score (0..1, where about 0.5 is ordinary):
	// 0.75 at the lowest setting, 0.70 at the default, 0.65 at the highest.
	neuralThresholdLeast = 0.75
	neuralThresholdSpan  = 0.10
)

// SetLowPower toggles the low-power mode for the ML engine.
func (d *NeuralAnomalyDetector) SetLowPower(enabled bool) {
	if enabled {
		atomic.StoreInt32(&d.LowPower, 1)
	} else {
		atomic.StoreInt32(&d.LowPower, 0)
	}
}

// Detect reports the clients the forest isolates whose traffic is harmful.
//
// Under CPU pressure (low power) the pass is skipped. It used to run a quarter
// of the trees instead, which roughly doubles the spread of every score: the
// saving is a few milliseconds a minute, and the price was a noisier detector
// whose findings can throttle.
func (d *NeuralAnomalyDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	threshold, on := neuralThreshold(d.Config)
	if !on || atomic.LoadInt32(&d.LowPower) == 1 {
		return nil
	}
	pop := neuralPopulation(data)
	if len(pop.ips) < neuralMinPopulation {
		return nil
	}
	scores, err := isolationScores(pop.features)
	if err != nil {
		logger.L.LogWarn("neural sentinel could not score the analysis window", "error", err)
		return nil
	}
	var findings []*gateonv1.Anomaly
	for i, score := range scores {
		if score < threshold {
			continue
		}
		harm, harmful := pop.stats[i].harmEvidence(data.TraceSampleRate)
		if !harmful {
			continue
		}
		f := pop.finding(i, score, threshold, harm)
		populateAnomalyGeo(ctx, f, pop.ips[i])
		findings = append(findings, f)
	}
	return findings
}

// neuralThreshold is the isolation score at or above which a client is
// anomalous, and whether the detector runs at all.
//
// Sensitivity is the dashboard's 0..1 slider. The detector used to read it as
// 0..100, so the default 0.5 set the bar at 0.898 of a score this library
// cannot produce, and a Sensitivity of 0 fell through to 0.7, the more
// sensitive setting. Now higher is more sensitive, and 0 switches the detector
// off, as it does every other check the slider governs.
func neuralThreshold(cfg *gateonv1.AnomalyDetectionConfig) (float64, bool) {
	if cfg == nil || !cfg.GetEnabled() || cfg.GetSensitivity() <= 0 {
		return 0, false
	}
	s := math.Min(cfg.GetSensitivity(), 1)
	return neuralThresholdLeast - neuralThresholdSpan*s, true
}

// neuralPopulationStats is the analysis window's measurable clients, their
// feature vectors and their records, index-aligned.
type neuralPopulationStats struct {
	ips      []string
	stats    []*IPStats
	features [][]float64
	now      time.Time
}

// neuralPopulation collects every client with enough traced requests to
// measure, in a stable order.
func neuralPopulation(data *DiagnosticData) *neuralPopulationStats {
	pop := &neuralPopulationStats{now: data.now()}
	for ip, st := range data.IPStats {
		if st.TotalRequests >= neuralMinRequests {
			pop.ips = append(pop.ips, ip)
		}
	}
	slices.Sort(pop.ips)
	for _, ip := range pop.ips {
		st := data.IPStats[ip]
		pop.stats = append(pop.stats, st)
		pop.features = append(pop.features, neuralFeatures(st, data.TraceSampleRate))
	}
	return pop
}

// neuralFeatureNames names neuralFeatures' columns for the finding's
// explanation, in order.
var neuralFeatureNames = [...]string{
	"share of requests failing", "share refused 401/403", "share not found", "failed requests",
	"failures on its most-failed path", "distinct failing paths", "share caught as attacks",
	"typical gap between requests", "irregularity of those gaps",
}

// neuralFeatures is what the forest isolates a client on: seven measures of
// harm and two of rhythm, each scaled so that no one of them dominates by its
// units. Shares are taken over the requests the client really sent
// (estimatedRequests); counts are logarithmic.
//
// Volume, response time and path variety are left out on purpose: they are
// what makes an office's egress, a CI runner or a crawler unusual, and none of
// them is harm.
func neuralFeatures(st *IPStats, sampleRate uint32) []float64 {
	requests := st.estimatedRequests(sampleRate)
	failures := float64(st.Failures())
	mostFailed := 0
	for _, n := range st.FailedPaths {
		mostFailed = max(mostFailed, n)
	}
	meanGap, irregularity := gapStatistics(st)
	return []float64{
		failures / requests,
		float64(st.Error401+st.Error403) / requests,
		float64(st.Error404) / requests,
		math.Log1p(failures),
		math.Log1p(float64(mostFailed)),
		math.Log1p(float64(len(st.FailedPaths))),
		math.Min(1, st.AttackEvidence/requests),
		math.Log1p(meanGap),
		irregularity,
	}
}

// gapStatistics is the mean gap between a client's requests, in milliseconds,
// and the gaps' coefficient of variation, capped at 3 (a page load's burst
// followed by a minute of reading is already far past any machine's rhythm).
func gapStatistics(st *IPStats) (float64, float64) {
	if st.IATCount == 0 {
		return 0, 0
	}
	mean := st.IATSum / float64(st.IATCount)
	variance := st.IATSumSq/float64(st.IATCount) - mean*mean
	if mean <= 0 || variance <= 0 {
		return mean, 0
	}
	return mean, math.Min(3, math.Sqrt(variance)/mean)
}

// forestMu serializes forest training. go-iforest's Train writes the
// package-global iforest.MaxDepth that every tree it builds then reads, so two
// passes training at once -- the analysis loop and a Diagnostics request, or
// two requests -- raced on it.
var forestMu sync.Mutex

// isolationScores fits an isolation forest to the population and returns each
// client's standard anomaly score, 2^(-E(h)/c(n)): about 0.5 for a typical
// member, approaching 1 for one that isolates in a split or two.
//
// The library is used as its production code requires, which is not what its
// method names suggest:
//
//   - Predict refuses a forest that has not been through Test (its error says
//     the model "has not been tested yet"), and the detector used to call Train
//     and then Predict, so it never scored anything;
//   - the subsample is capped at the population. Asked for 256 from fewer
//     clients, Train pads each tree's sample with row 0 -- one arbitrary client
//     repeated a couple of hundred times -- and normalises path lengths by c(256)
//     rather than the population's, which inflates every score;
//   - the library reports 0.5 - 2^(-E(h)/c(n)), in [-0.5, 0.5) with anomalies
//     at the LOW end, so it is turned back into the standard score here.
func isolationScores(features [][]float64) ([]float64, error) {
	forestMu.Lock()
	defer forestMu.Unlock()
	forest := iforest.NewForest(neuralTrees, min(len(features), neuralMaxSubsample), neuralAnomalyRatio)
	forest.Train(features)
	if err := forest.Test(features); err != nil {
		return nil, err
	}
	_, libraryScores, err := forest.Predict(features)
	if err != nil {
		return nil, err
	}
	scores := make([]float64, len(libraryScores))
	for i, s := range libraryScores {
		scores[i] = 0.5 - s
	}
	return scores, nil
}

// finding is the anomaly for population member i.
func (pop *neuralPopulationStats) finding(i int, score, threshold float64, harm string) *gateonv1.Anomaly {
	ip, st := pop.ips[i], pop.stats[i]
	severity := severityMedium
	if score >= threshold+0.1 {
		severity = severityHigh
	}
	at := st.LastSeen
	if at.IsZero() {
		at = pop.now
	}
	return &gateonv1.Anomaly{
		Type:     neuralSentinelType,
		Severity: severity,
		Description: fmt.Sprintf("Neural Sentinel: %s behaves unlike the other %d measured clients "+
			"(isolation score %.2f, reported from %.2f) and its traffic is harmful: %s. Most unlike the rest in: %s.",
			ip, len(pop.ips)-1, score, threshold, harm, pop.explain(i)),
		Source:     ip,
		Score:      score * 100,
		Confidence: math.Min(1, (score-threshold)/(1-threshold)),
		Timestamp:  at.Format(time.RFC3339),
		Recommendation: "Review this client's recent requests. Repeated findings rate-limit it in the kernel " +
			"(where eBPF is attached); releasing its mitigation lifts the limit and resets that history.",
	}
}

// explain names the two features on which member i stands furthest from the
// population's median, measured in each feature's own spread.
func (pop *neuralPopulationStats) explain(i int) string {
	type deviation struct {
		name string
		by   float64
	}
	devs := make([]deviation, 0, len(neuralFeatureNames))
	column := make([]float64, len(pop.features))
	for f, name := range neuralFeatureNames {
		for r, row := range pop.features {
			column[r] = row[f]
		}
		slices.Sort(column)
		median, spread := column[len(column)/2], column[len(column)-1]-column[0]
		if spread <= 0 {
			continue
		}
		devs = append(devs, deviation{name, math.Abs(pop.features[i][f]-median) / spread})
	}
	slices.SortStableFunc(devs, func(a, b deviation) int { return cmp.Compare(b.by, a.by) })
	parts := make([]string, 0, 2)
	for _, d := range devs[:min(2, len(devs))] {
		parts = append(parts, d.name)
	}
	return strings.Join(parts, " and ")
}
