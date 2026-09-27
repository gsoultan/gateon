// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// TokenEnv names the environment variable `gateon top` reads its management
// API token from when --token is not given.
const TokenEnv = "GATEON_TOKEN"

// fetchTimeout bounds one poll of the management API, so a gateway that stops
// answering leaves the screen saying so instead of hanging it.
const fetchTimeout = 5 * time.Second

type routeStat struct {
	ID         string
	Requests   uint64
	Errors     uint64
	Latency    float64 // milliseconds, averaged over the route's requests
	ActiveConn int64
}

// targetStats is one backend target's counters as GET /v1/routes/stats sends them.
type targetStats struct {
	RequestCount uint64 `json:"requestCount"`
	ErrorCount   uint64 `json:"errorCount"`
	AvgLatencyUs uint64 `json:"avgLatencyUs"`
	ActiveConn   int64  `json:"activeConn"`
}

// errUnauthorized is what a poll answers when the management API wants a
// token it was not given, or refused the one it was.
var errUnauthorized = errors.New("the management API refused the request (401): sign in with POST /v1/login " +
	"and pass the token with --token or " + TokenEnv)

// TopArgs reads `gateon top [API URL] [--token TOKEN]`. The token is the one
// POST /v1/login returns to an API client; without --token it comes from the
// GATEON_TOKEN environment variable, which keeps it out of the process list.
func TopArgs(args []string, defaultURL string) (apiURL, token string) {
	apiURL, token = defaultURL, os.Getenv(TokenEnv)
	for i := 0; i < len(args); i++ {
		switch arg := args[i]; {
		case arg == "--token" && i+1 < len(args):
			token = args[i+1]
			i++
		case strings.HasPrefix(arg, "--token="):
			token = strings.TrimPrefix(arg, "--token=")
		case !strings.HasPrefix(arg, "-"):
			apiURL = arg
		}
	}
	return apiURL, token
}

// RunTop polls the management API every two seconds and draws a table of the
// routes' traffic. token, when set, is sent as a Bearer credential: the
// management API answers nothing without one when authentication is on.
func RunTop(ctx context.Context, apiURL, token string) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	client := &http.Client{Timeout: fetchTimeout}

	fmt.Print("\033[H\033[2J") // Clear screen

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			stats, err := fetchStats(ctx, client, apiURL, token)
			if errors.Is(err, errUnauthorized) {
				return err
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching stats: %v\n", err)
				continue
			}
			draw(apiURL, stats)
		}
	}
}

func draw(apiURL string, stats []routeStat) {
	fmt.Print("\033[H") // Move cursor to top
	fmt.Printf("Gateon Top - %s - API: %s\n", time.Now().Format(time.RFC1123), apiURL)
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("%-20s %10s %10s %10s %10s\n", "ROUTE ID", "REQS", "ERRS", "LAT(ms)", "CONNS")
	fmt.Println(strings.Repeat("-", 80))
	for _, s := range stats {
		fmt.Printf("%-20s %10d %10d %10.2f %10d\n",
			truncate(s.ID, 20), s.Requests, s.Errors, s.Latency, s.ActiveConn)
	}
}

// fetchStats reads GET /v1/routes/stats -- each route's per-target counters --
// and sums them per route, busiest first. It used to read /v1/status, which
// carries no per-route numbers, without credentials, so the table was always
// empty and, with authentication on, every poll was refused.
func fetchStats(ctx context.Context, client *http.Client, apiURL, token string) ([]routeStat, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/v1/routes/stats", nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, errUnauthorized
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("the management API answered %s", resp.Status)
	}
	var byRoute map[string][]targetStats
	if err := json.NewDecoder(resp.Body).Decode(&byRoute); err != nil {
		return nil, err
	}
	return summarize(byRoute), nil
}

// summarize adds each route's targets together; latency is weighted by each
// target's share of the route's requests.
func summarize(byRoute map[string][]targetStats) []routeStat {
	stats := make([]routeStat, 0, len(byRoute))
	for id, targets := range byRoute {
		s := routeStat{ID: id}
		var latencySumUs float64
		for _, t := range targets {
			s.Requests += t.RequestCount
			s.Errors += t.ErrorCount
			s.ActiveConn += t.ActiveConn
			latencySumUs += float64(t.AvgLatencyUs) * float64(t.RequestCount)
		}
		if s.Requests > 0 {
			s.Latency = latencySumUs / float64(s.Requests) / 1000
		}
		stats = append(stats, s)
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Requests != stats[j].Requests {
			return stats[i].Requests > stats[j].Requests
		}
		return stats[i].ID < stats[j].ID
	})
	return stats
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
