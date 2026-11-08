// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Command seed provisions the dev admin/operator/viewer accounts so the
// dashboard is usable the moment gateon starts, skipping the first-run wizard.
// It is idempotent (a re-run resets the accounts), takes the database URL and PASETO secret from
// flags or env so it uses the exact store the running gateway will, and is a
// dev-only convenience — production provisions through the setup flow.
//
// Each account's password is its own name (admin/admin, operator/operator,
// viewer/viewer), which the password policy (ADR 0050) refuses everywhere a
// password can be set. The policy is not relaxed for this: the seed writes the
// hash itself, and only into a database that is plainly a developer's — a
// SQLite file under a dev/.data directory, or a Postgres on a loopback
// address. Anything else is refused before a row is touched.
//
//	go run ./dev/seed -db dev/.data/gateon-dev.db -secret <32-char-secret>
package main

import (
	"errors"
	"flag"
	"log"
	"os"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/auth/passpolicy"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// account is one seeded login.
type account struct {
	username, role string
}

var accounts = []account{
	{"admin", auth.RoleAdmin},
	{"operator", auth.RoleOperator},
	{"viewer", auth.RoleViewer},
}

func main() {
	db := flag.String("db", os.Getenv("GATEON_DEV_DB"), "auth database URL/path")
	secret := flag.String("secret", os.Getenv("GATEON_DEV_PASETO"), "PASETO secret (exactly 32 chars)")
	password := flag.String("password", os.Getenv("GATEON_DEV_PASSWORD"),
		"one password for every seeded account (default: each account's own name)")
	flag.Parse()

	if *db == "" || len(*secret) != 32 {
		// #nosec G706 -- developer seeding tool; the values are flags this
		// operator just typed and the sink is their own terminal.
		log.Fatalf("seed: -db is required and -secret must be exactly 32 characters (got db=%q, secret len=%d)", *db, len(*secret))
	}

	_ = logger.Init(false)
	mgr, err := auth.NewManager(*db, *secret, logger.Default())
	if err != nil {
		log.Fatalf("seed: init auth manager: %v", err)
	}
	defer mgr.Close()

	weak := false
	for _, a := range accounts {
		w, err := seedAccount(mgr, *db, a, passwordFor(a, *password))
		if err != nil {
			log.Fatalf("seed: %s: %v", a.username, err)
		}
		weak = weak || w
	}
	// The password is deliberately not logged. scripts/dev.sh prints it in its
	// banner, so echoing it here buys nothing and writes a credential into
	// whatever collects this output.
	// #nosec G706 -- a developer seeding tool; *db is a flag this operator just
	// typed, and the sink is their own terminal.
	log.Printf("seed: admin/operator/viewer ready in %s", *db)
	if weak {
		log.Print("seed: WARNING these accounts use passwords the password policy refuses. " +
			"This database is for local development only; never point a reachable gateway at it.")
	}
}

// passwordFor is the password a seeded account gets: the override when one was
// given, otherwise the account's own name.
func passwordFor(a account, override string) string {
	if override != "" {
		return override
	}
	return a.username
}

// seedAccount creates or resets a, and reports whether its password is one
// the policy refuses. Such a password is stored by writing its hash directly,
// and only when dbURL is a developer's own database.
func seedAccount(mgr *auth.Manager, dbURL string, a account, password string) (bool, error) {
	id := existingID(mgr, a.username)
	err := upsert(mgr, id, a, password)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, passpolicy.ErrWeak) {
		return false, err
	}
	if err := requireDevDatabase(dbURL); err != nil {
		return false, err
	}
	// The account has to exist before its hash can be replaced, and creating
	// it needs a password the policy accepts. That password is random and
	// overwritten on the next line, so nobody ever knows it.
	placeholder, err := randomPassword()
	if err != nil {
		return false, err
	}
	if err := upsert(mgr, id, a, placeholder); err != nil {
		return false, err
	}
	return true, setPasswordHash(dbURL, a.username, password)
}

func upsert(mgr *auth.Manager, id string, a account, password string) error {
	return mgr.UpsertUser(&gateonv1.User{
		Id:       id,
		Username: a.username,
		Password: password,
		Role:     a.role,
	})
}

// existingID returns the id of the account named username, or "" when there is
// none. UpsertUser creates an account only under a name nobody has; given the
// id it resets the existing one instead, which is what a re-run seed wants.
func existingID(mgr *auth.Manager, username string) string {
	users, _, err := mgr.ListUsers(0, 100, username)
	if err != nil {
		return ""
	}
	for _, u := range users {
		if u.Username == username {
			return u.Id
		}
	}
	return ""
}
