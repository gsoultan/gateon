// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Command seed provisions the dev admin/operator/viewer accounts so the
// dashboard is usable the moment gateon starts, skipping the first-run wizard.
// It is idempotent (a re-run resets the accounts), takes the database URL and PASETO secret from
// flags or env so it uses the exact store the running gateway will, and is a
// dev-only convenience — production provisions through the setup flow.
//
//	go run ./dev/seed -db dev/.data/gateon-dev.db -secret <32-char-secret>
package main

import (
	"flag"
	"log"
	"os"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func main() {
	db := flag.String("db", os.Getenv("GATEON_DEV_DB"), "auth database URL/path")
	secret := flag.String("secret", os.Getenv("GATEON_DEV_PASETO"), "PASETO secret (exactly 32 chars)")
	password := flag.String("password", envOr("GATEON_DEV_PASSWORD", "password123"), "password for the seeded accounts")
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

	accounts := []struct {
		username, role string
	}{
		{"admin", auth.RoleAdmin},
		{"operator", auth.RoleOperator},
		{"viewer", auth.RoleViewer},
	}
	for _, a := range accounts {
		if err := mgr.UpsertUser(&gateonv1.User{
			Id:       existingID(mgr, a.username),
			Username: a.username,
			Password: *password,
			Role:     a.role,
		}); err != nil {
			log.Fatalf("seed: create %s: %v", a.username, err)
		}
	}
	// The password is deliberately not logged. It is a known dev default and
	// scripts/dev.sh prints it in its banner, so echoing it here buys nothing
	// and writes a credential into whatever collects this output.
	// #nosec G706 -- a developer seeding tool; *db is a flag this operator just
	// typed, and the sink is their own terminal.
	log.Printf("seed: admin/operator/viewer ready in %s", *db)
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

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
