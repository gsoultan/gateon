// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/gsoultan/gateon/internal/audit"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// defaultEnvFile is where the packaged unit reads the gateway's secrets from.
const defaultEnvFile = "/etc/default/gateon"

// unitName is the packaged systemd unit.
const unitName = "gateon"

// currentEUID is os.Geteuid, a variable so the refusal of a caller who is not
// root can be tested by a test that is, and the reset by one that is not.
var currentEUID = os.Geteuid

const adminUsage = `usage: gateon admin reset <username> [--create] [--env-file PATH]

Gives <username> back to whoever holds the host: an enabled administrator with
a new random password, its second factor cleared and owed at the next sign-in,
and every session of every account ended. Run it as root with the gateway
stopped. See doc/incident-compromise.md.
`

// adminCLI runs `gateon admin <command>` and returns the exit status.
func adminCLI(args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] != "reset" {
		fmt.Fprint(errOut, adminUsage)
		return 2
	}
	opts, err := parseResetArgs(args[1:])
	if err != nil {
		fmt.Fprintf(errOut, "admin reset: %v\n\n%s", err, adminUsage)
		return 2
	}
	if err := checkResetPreconditions(opts); err != nil {
		fmt.Fprintf(errOut, "admin reset: %v\n", err)
		return 1
	}
	rec, err := resetAdministrator(opts)
	if err != nil {
		fmt.Fprintf(errOut, "admin reset: %v\n", err)
		return 1
	}
	printRecovery(out, opts.username, rec)
	return 0
}

// resetOptions is what `admin reset` was asked to do.
type resetOptions struct {
	username string
	create   bool
	envFile  string
}

// parseResetArgs reads the username and flags, in either order.
func parseResetArgs(args []string) (resetOptions, error) {
	var o resetOptions
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		o.username, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("admin reset", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&o.create, "create", false, "create the account when it does not exist")
	fs.StringVar(&o.envFile, "env-file", defaultEnvFile, "the gateway's environment file")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if o.username == "" && fs.NArg() > 0 {
		o.username = fs.Arg(0)
	}
	if strings.TrimSpace(o.username) == "" {
		return o, errors.New("name the account to reset")
	}
	return o, nil
}

// checkResetPreconditions refuses a caller who is not root, and a gateway
// systemd says is running.
//
// Root, because this hands an administrator's account to whoever runs it:
// it is the host's administrator's decision, made on the host. Stopped,
// because a running gateway holds its lockout state in memory and would go
// on refusing the account it was just given back.
func checkResetPreconditions(o resetOptions) error {
	if currentEUID() != 0 {
		return errors.New("run it as root (sudo gateon admin reset ...)")
	}
	if err := loadEnvFile(o.envFile, o.envFile != defaultEnvFile); err != nil {
		return err
	}
	if gatewayRunning() {
		return fmt.Errorf("the gateway is running; stop it first (sudo systemctl stop %s)", unitName)
	}
	return nil
}

// gatewayRunning reports whether systemd says the packaged unit is active.
// Without systemd there is nothing to ask, and the operator is trusted.
func gatewayRunning() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	// #nosec G204 -- constant arguments.
	return exec.Command("systemctl", "is-active", "--quiet", unitName).Run() == nil
}

// loadEnvFile sets each KEY=VALUE in path that the environment does not
// already set, as systemd's EnvironmentFile= does for the unit. A missing
// file is an error only when it was named explicitly.
func loadEnvFile(path string, required bool) error {
	f, err := os.Open(path) // #nosec G304 -- a path root named on the command line.
	if errors.Is(err, os.ErrNotExist) && !required {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, val, ok := envLine(sc.Text())
		if _, set := os.LookupEnv(key); ok && !set {
			if err := os.Setenv(key, val); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}

// envLine parses one EnvironmentFile line.
func envLine(line string) (key, val string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' || line[0] == ';' {
		return "", "", false
	}
	key, val, ok = strings.Cut(strings.TrimPrefix(line, "export "), "=")
	key = strings.TrimSpace(key)
	val = strings.TrimSpace(val)
	if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[len(val)-1] == val[0] {
		val = val[1 : len(val)-1]
	}
	return key, val, ok && key != ""
}

// resetAdministrator opens the gateway's own configuration and user
// database, recovers the account, records it in the audit log, and hands
// every SQLite file it wrote back to the account that owned it.
func resetAdministrator(o resetOptions) (auth.Recovery, error) {
	gc, err := loadGatewayConfig()
	if err != nil {
		return auth.Recovery{}, err
	}
	authURL := db.AuthDatabaseURL(gc.GetAuth())
	auditURL := db.AuditDatabaseURL(gc.GetAudit(), gc.GetAuth())
	defer keepOwners(authURL, auditURL)()

	m, err := auth.NewManager(authURL, gc.GetAuth().GetPasetoSecret(), logger.Default())
	if err != nil {
		return auth.Recovery{}, fmt.Errorf("open the user database: %w", err)
	}
	defer m.Close()
	rec, err := m.RecoverAdministrator(o.username, o.create)
	if err != nil {
		return auth.Recovery{}, err
	}
	recordReset(gc, auditURL, o.username, rec)
	return rec, nil
}

// loadGatewayConfig reads the global configuration the gateway runs on.
func loadGatewayConfig() (*gateonv1.GlobalConfig, error) {
	path := getEnvDefault("GLOBAL_CONFIG_FILE", "global.json")
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("no gateway configuration at %s (set GLOBAL_CONFIG_FILE or GATEON_CONFIG_DIR): %w", path, err)
	}
	reg := config.NewGlobalRegistry(path)
	if err := reg.LoadErr(); err != nil {
		return nil, err
	}
	return reg.Get(context.Background()), nil
}

// recordReset writes the reset to the audit log, under the gateway's own
// audit settings, so the chain records it like any other change. A failure
// to record is reported and does not undo the reset: the account is back.
func recordReset(gc *gateonv1.GlobalConfig, auditURL, username string, rec auth.Recovery) {
	if err := audit.Init(gc.GetAudit(), auditURL); err != nil {
		fmt.Fprintf(os.Stderr, "admin reset: the reset is done but was not recorded in the audit log: %v\n", err)
		return
	}
	verb := "Reset"
	if rec.Created {
		verb = "Created"
	}
	audit.Log(context.Background(), "root@host", "admin_reset", "auth", fmt.Sprintf(
		"%s administrator %s from the host: new password, second factor owed, sessions of %d accounts ended",
		verb, username, rec.SessionsEnded), "local")
	audit.Stop()
}

// keepOwners records who owns each SQLite file behind urls and returns the
// function that gives them, and the journal files beside them, back. Root
// writing a database the gateway's own account must then open is the one
// way this command could take the gateway down instead of letting it back in.
func keepOwners(urls ...string) func() {
	type owned struct {
		path     string
		uid, gid int
	}
	var files []owned
	for _, u := range urls {
		if path, ok := db.SQLiteFile(u); ok {
			if uid, gid, ok := fileOwner(path); ok {
				files = append(files, owned{path, uid, gid})
			}
		}
	}
	return func() {
		for _, f := range files {
			for _, p := range []string{f.path, f.path + "-wal", f.path + "-shm", f.path + "-journal"} {
				if err := chownIfPresent(p, f.uid, f.gid); err != nil {
					fmt.Fprintf(os.Stderr, "admin reset: could not give %s back to its owner: %v\n", p, err)
				}
			}
		}
	}
}

func printRecovery(out io.Writer, username string, rec auth.Recovery) {
	what := "reset"
	if rec.Created {
		what = "created"
	}
	fmt.Fprintf(out, "Administrator %q %s. Sessions of %d accounts were ended.\n\n", username, what, rec.SessionsEnded)
	fmt.Fprintf(out, "  Password: %s\n\n", rec.Password)
	fmt.Fprintln(out, "It is shown once. Start the gateway, sign in with it, set up the second factor it asks")
	fmt.Fprintln(out, "for, change the password, then follow doc/incident-compromise.md: review every")
	fmt.Fprintln(out, "account, rotate the session key, and read the audit log from your off-host copy.")
}
