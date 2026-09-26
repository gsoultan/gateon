// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"errors"
	"fmt"
	neturl "net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// ErrNoDatabase is Probe's answer when neither the url nor the config names a
// database it can build a DSN for.
var ErrNoDatabase = errors.New("missing database configuration")

// errUnreachable is what Probe says of every Postgres failure short of a
// server answering.
var errUnreachable = errors.New("could not connect to a database server at that address; " +
	"check the host, port and SSL mode (the gateway's log has the detail)")

// errUnparsableURL is said instead of the parser's error, which quotes the url,
// password and all.
var errUnparsableURL = errors.New("the database url could not be parsed")

// probeTimeout bounds a Postgres probe from dial to startup, and is how long
// every failure short of a server answering takes. A variable so a test can
// shorten it.
var probeTimeout = 5 * time.Second

// Probe proves a database named over the network can be opened: databaseURL
// wins over cfg, a SQLite one must be a plain file inside dataDir (see
// ConfineSQLite), and the connection is closed as soon as it answers.
//
// It is what the first-run wizard's connection test and Setup itself run, so
// the database an operator tested is judged by the same rules as the one they
// submit. Both run before anyone has signed in, which is what probeFailure is
// about.
func Probe(databaseURL string, cfg *gateonv1.DatabaseConfig, dataDir string) error {
	dsn := databaseURL
	if dsn == "" {
		dsn = BuildURLFromConfig(cfg)
	}
	if dsn == "" {
		return ErrNoDatabase
	}
	if err := ConfineSQLite(dsn, dataDir); err != nil {
		return err
	}
	if driver, _ := parseURL(dsn); driver != DriverPostgres {
		conn, _, err := Open(dsn)
		if err != nil {
			return fmt.Errorf("failed to connect to database: %w", err)
		}
		_ = conn.Close()
		return nil
	}
	bounded, err := withConnectTimeout(dsn, probeTimeout)
	if err != nil {
		return err
	}
	start := time.Now()
	conn, _, err := Open(bounded)
	if err != nil {
		return probeFailure(err, start)
	}
	_ = conn.Close()
	return nil
}

// probeFailure is what a failed Postgres probe may tell its caller, who has not
// signed in.
//
// The driver's own error told a refused port from a filtered one, and either
// from a service that is not Postgres, so until setup completed the connection
// test was a port scanner for the gateway's network. Only what a Postgres server
// said is passed on -- what an operator fixing a user name, a password or a
// database name needs -- and every other failure reads the same and takes the
// whole timeout, so time does not tell them apart either. The full error goes
// to the log, with any password in it removed.
func probeFailure(err error, start time.Time) error {
	logger.L.LogWarn("database connection test failed", "error", redactPassword(err.Error()))
	var pgErr *pq.Error
	switch {
	case errors.As(err, &pgErr):
		return fmt.Errorf("the database server refused the connection: %s", pgErr.Message)
	case errors.Is(err, pq.ErrSSLNotSupported):
		return errors.New("the database server does not accept SSL; set the SSL mode to disable, or enable SSL on the server")
	}
	time.Sleep(time.Until(start.Add(probeTimeout)))
	return errUnreachable
}

// withConnectTimeout bounds the probe from dial to startup -- lib/pq's
// connect_timeout covers both -- replacing any value the url carried. The probe
// is the gateway's: left to the url, or unset, it waited as long as the far end
// did, holding the request and a connection to an address the caller chose.
func withConnectTimeout(dsn string, timeout time.Duration) (string, error) {
	u, err := neturl.Parse(dsn)
	if err != nil {
		return "", errUnparsableURL
	}
	q := u.Query()
	for key := range q {
		if strings.EqualFold(key, "connect_timeout") {
			q.Del(key)
		}
	}
	q.Set("connect_timeout", strconv.Itoa(max(1, int(timeout/time.Second))))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// passwordInURL matches the password in a url's userinfo, which an error from
// a driver can quote whole.
var passwordInURL = regexp.MustCompile(`(://[^:/@\s]*):[^@\s]*@`)

func redactPassword(s string) string {
	return passwordInURL.ReplaceAllString(s, "$1:REDACTED@")
}
