// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Command seed_trace_archive gives the e2e gateway's trace archive another
// node's hour to show. It records traces from two days ago into a throwaway
// trace store and archives them, as the node gw-seed, into
// GATEON_TRACE_ARCHIVE_DIR: the directory the gateway under test reads, shared
// the way gateways share an archive on common storage (ADR-0023). The store is
// deleted afterwards; the archived hour is all that is left of it. -node and
// -ago archive a different node's hour, or a different hour.
//
// The gateway cannot make such an hour itself during a run: it archives an
// hour only once the hour has ended.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/tracearchive"
)

// seeded are the hour's traces: each path is unique to this seed, so the spec
// can tell them from anything else a run records.
var seeded = []struct {
	method, path, status string
}{
	{"GET", "/archived/orders/1", "200"},
	{"POST", "/archived/orders", "201"},
	{"GET", "/archived/orders/2", "404"},
	{"GET", "/archived/payments", "502"},
	{"DELETE", "/archived/orders/3", "204"},
}

func main() {
	// tests/trace-archive.spec.ts looks for the defaults.
	node := flag.String("node", "gw-seed", "the node to archive the hour as")
	ago := flag.Duration("ago", 48*time.Hour, "how long ago the hour to seed was")
	flag.Parse()
	root := os.Getenv(tracearchive.EnvDir)
	if root == "" {
		log.Fatalf("%s must name the archive to seed", tracearchive.EnvDir)
	}
	store, err := os.MkdirTemp("", "gateon-seed-store-")
	if err != nil {
		log.Fatalf("seed store: %v", err)
	}
	err = seed(root, store, *node, time.Now().UTC().Add(-*ago).Truncate(time.Hour))
	_ = os.RemoveAll(store)
	if err != nil {
		log.Fatal(err)
	}
}

func seed(root, store, node string, hour time.Time) error {
	for k, v := range map[string]string{
		"GATEON_TRACE_DIR":       filepath.Join(store, "pebble"),
		tracearchive.EnvEnabled:  "true",
		tracearchive.EnvNodeName: node,
	} {
		if err := os.Setenv(k, v); err != nil {
			return err
		}
	}
	ctx := context.Background()
	if err := telemetry.InitPathStatsStore(filepath.Join(store, "telemetry.db"), 7); err != nil {
		return fmt.Errorf("seed store: %w", err)
	}
	for i, s := range seeded {
		telemetry.RecordTrace(fmt.Sprintf("%s-trace-%d", node, i+1), s.method+" "+s.path, "archive-demo", "archive-demo-route",
			12.5+float64(i), hour.Add(time.Duration(10+i*7)*time.Minute), s.status, s.path,
			fmt.Sprintf("198.51.100.%d", 10+i), "", "NL", "curl/8.7.1", s.method, "", s.path, "", "",
			map[string][]string{"Accept": {"application/json"}}, nil, "none", 0, 0, 0, 0, 0)
	}
	telemetry.FlushTraces()
	(&tracearchive.Archiver{}).ArchiveNow(ctx)
	if err := telemetry.ClosePathStatsStore(ctx); err != nil {
		return fmt.Errorf("seed store: %w", err)
	}

	segs, _, err := tracearchive.List(hour, hour.Add(time.Hour), 10, "")
	if err != nil {
		return fmt.Errorf("list the seeded archive: %w", err)
	}
	segs = slices.DeleteFunc(segs, func(s tracearchive.SegmentSummary) bool { return s.Node != node })
	if len(segs) != 1 || segs[0].Traces != int64(len(seeded)) {
		return fmt.Errorf("the seeded hour did not archive: %+v in %s", segs, root)
	}
	log.Printf("seeded %s with %d of %s's traces in %s", segs[0].Name(), segs[0].Traces, node, root)
	return nil
}
