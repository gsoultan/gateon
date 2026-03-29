package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

type routeStat struct {
	ID         string  `json:"id"`
	Requests   int64   `json:"requests"`
	Errors     int64   `json:"errors"`
	Latency    float64 `json:"latency"`
	ActiveConn int64   `json:"active_conn"`
}

func RunTop(ctx context.Context, apiURL string) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	fmt.Print("\033[H\033[2J") // Clear screen

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			stats, err := fetchStats(apiURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching stats: %v\n", err)
				continue
			}

			fmt.Print("\033[H") // Move cursor to top
			fmt.Printf("Gateon Top - %s - API: %s\n", time.Now().Format(time.RFC1123), apiURL)
			fmt.Println(strings.Repeat("-", 80))
			fmt.Printf("%-20s %10s %10s %10s %10s\n", "ROUTE ID", "REQS", "ERRS", "LAT(ms)", "CONNS")
			fmt.Println(strings.Repeat("-", 80))

			sort.Slice(stats, func(i, j int) bool {
				return stats[i].Requests > stats[j].Requests
			})

			for _, s := range stats {
				fmt.Printf("%-20s %10d %10d %10.2f %10d\n",
					truncate(s.ID, 20), s.Requests, s.Errors, s.Latency, s.ActiveConn)
			}
		}
	}
}

func fetchStats(apiURL string) ([]routeStat, error) {
	// Note: In a real implementation we would fetch from /v1/status or /metrics
	// For now we'll fetch /v1/status which returns route metrics
	resp, err := http.Get(apiURL + "/v1/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data struct {
		Routes map[string]routeStat `json:"routes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	stats := make([]routeStat, 0, len(data.Routes))
	for id, s := range data.Routes {
		s.ID = id
		stats = append(stats, s)
	}
	return stats, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func (s *routeStat) UnmarshalJSON(data []byte) error {
	type Alias routeStat
	aux := &struct {
		*Alias
		AvgLatencyMs  float64 `json:"avg_latency_ms"`
		RequestsTotal int64   `json:"requests_total"`
		ErrorsTotal   int64   `json:"errors_total"`
		ActiveConn    int64   `json:"active_conn"`
	}{
		Alias: (*Alias)(s),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	s.Latency = aux.AvgLatencyMs
	s.Requests = aux.RequestsTotal
	s.Errors = aux.ErrorsTotal
	s.ActiveConn = aux.ActiveConn
	return nil
}
