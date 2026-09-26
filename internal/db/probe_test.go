// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Probe is what the setup wizard's connection test and Setup both run on a
// database named before anyone has signed in, so the rules it applies are
// pinned here, in the package that owns it.
func TestProbe(t *testing.T) {
	dir := t.TempDir()

	t.Run("names nothing", func(t *testing.T) {
		for _, cfg := range []*gateonv1.DatabaseConfig{nil, {}, {Driver: "oracle"}} {
			if err := Probe("", cfg, dir); !errors.Is(err, ErrNoDatabase) {
				t.Errorf("Probe(\"\", %v) = %v, want ErrNoDatabase", cfg, err)
			}
		}
	})

	// The url is what Setup stores when both are given, so it has to be what
	// is tested: otherwise the wizard proves one database and saves another.
	t.Run("url wins over config", func(t *testing.T) {
		byURL, byConfig := filepath.Join(dir, "by-url.db"), filepath.Join(dir, "by-config.db")
		if err := Probe(byURL, &gateonv1.DatabaseConfig{Driver: "sqlite", SqlitePath: byConfig}, dir); err != nil {
			t.Fatalf("Probe: %v", err)
		}
		if _, err := os.Stat(byURL); err != nil {
			t.Errorf("the url's database was not opened: %v", err)
		}
		if _, err := os.Stat(byConfig); !os.IsNotExist(err) {
			t.Errorf("the config's database was opened although a url was given (stat err = %v)", err)
		}
	})

	t.Run("sqlite outside the data directory", func(t *testing.T) {
		escape := filepath.Join(t.TempDir(), "escape.db")
		err := Probe("", &gateonv1.DatabaseConfig{Driver: "sqlite", SqlitePath: escape}, dir)
		if !errors.Is(err, ErrSQLiteNotConfined) {
			t.Errorf("Probe = %v, want ErrSQLiteNotConfined", err)
		}
		if _, err := os.Stat(escape); !os.IsNotExist(err) {
			t.Errorf("a refused database was created (stat err = %v)", err)
		}
	})

	t.Run("unreachable server", func(t *testing.T) {
		// Loopback port 1: refused at once, without leaving this host.
		cfg := &gateonv1.DatabaseConfig{Driver: "postgres", Host: "127.0.0.1", Port: 1, User: "gateon", Database: "gateon"}
		if err := Probe("", cfg, dir); err == nil || !strings.Contains(err.Error(), "failed to connect to database") {
			t.Errorf("Probe = %v, want a connection failure", err)
		}
	})
}
