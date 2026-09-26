// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

}

// shortProbe makes a Postgres probe's bound one second for the test.
func shortProbe(t *testing.T) {
	t.Helper()
	prev := probeTimeout
	probeTimeout = time.Second
	t.Cleanup(func() { probeTimeout = prev })
}

// serveTCP accepts on loopback and hands each connection to handle, one at a
// time; the accept loop is joined when the test ends.
func serveTCP(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			handle(c)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		wg.Wait()
	})
	return l.Addr().String()
}

// TestProbeSaysTheSameOfEveryAddressThatIsNotPostgres: Probe runs for a
// caller who has not signed in, and it returned the driver's error, which told
// a refused port from one where something answered and hung up, and both from
// one that never answered. That made the setup wizard's connection test a port
// scanner for the gateway's network until setup completed. Every one of them
// must now read the same, and take the same time.
func TestProbeSaysTheSameOfEveryAddressThatIsNotPostgres(t *testing.T) {
	shortProbe(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	refused := l.Addr().String()
	_ = l.Close()
	hangsUp := serveTCP(t, func(c net.Conn) { _, _ = c.Read(make([]byte, 512)) })
	// connect_timeout=0 is lib/pq's "wait forever"; the probe's bound must win.
	silent := serveTCP(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })

	for name, addr := range map[string]string{"refused": refused, "hangs up": hangsUp, "silent": silent} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			err := Probe("postgres://gateon:secret@"+addr+"/gateon?sslmode=disable&connect_timeout=0", nil, t.TempDir())
			took := time.Since(start)
			if !errors.Is(err, errUnreachable) {
				t.Fatalf("Probe = %v, want errUnreachable", err)
			}
			if took < probeTimeout || took > probeTimeout+2*time.Second {
				t.Errorf("took %v, want the probe's bound of %v whatever the address did", took, probeTimeout)
			}
		})
	}
}

// postgresRefusing answers a startup message the way Postgres does when the
// password is wrong.
func postgresRefusing(c net.Conn) {
	var n uint32
	if binary.Read(c, binary.BigEndian, &n) != nil || n < 8 {
		return
	}
	if _, err := io.CopyN(io.Discard, c, int64(n-4)); err != nil {
		return
	}
	var body bytes.Buffer
	for _, field := range []string{"SFATAL", "VFATAL", "C28P01", `Mpassword authentication failed for user "gateon"`} {
		body.WriteString(field)
		body.WriteByte(0)
	}
	body.WriteByte(0)
	msg := binary.BigEndian.AppendUint32([]byte{'E'}, uint32(body.Len()+4))
	_, _ = c.Write(append(msg, body.Bytes()...))
}

// What a Postgres server said is what an operator needs to fix the user, the
// password or the database, and it tells the caller nothing a port does not:
// it is passed on, at once.
func TestProbePassesOnWhatAPostgresServerSaid(t *testing.T) {
	shortProbe(t)
	addr := serveTCP(t, postgresRefusing)
	start := time.Now()
	err := Probe("postgres://gateon:wrong@"+addr+"/gateon?sslmode=disable", nil, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), `password authentication failed for user "gateon"`) {
		t.Fatalf("Probe = %v, want the server's own words", err)
	}
	if took := time.Since(start); took >= probeTimeout {
		t.Errorf("took %v; a server's answer is not held back to the probe's bound", took)
	}
}

func TestProbeKeepsPasswordsOutOfTheLog(t *testing.T) {
	got := redactPassword(`parse "postgres://gateon:s3cr3t@db.internal:5432/gateon": invalid port`)
	if strings.Contains(got, "s3cr3t") || !strings.Contains(got, "gateon:REDACTED@db.internal") {
		t.Errorf("redactPassword = %q", got)
	}
}
