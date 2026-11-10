// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package devpostgres

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const defaultPort = 54329

// fakeContainer stands in for Apple's `container` CLI. It keeps one container's
// state in $FAKE_DIR and, like the real one, fails `run` and `start` with a
// bind() error when the published host port is already taken.
const fakeContainer = `#!/usr/bin/env bash
set -u
d="${FAKE_DIR}"
busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
case "$1" in
  ls) exit 0 ;;
  inspect)
    [ -f "$d/state" ] || exit 1
    printf '[{"status":{"state":"%s"}}]\n' "$(cat "$d/state")" ;;
  run)
    shift; port=""
    while [ $# -gt 0 ]; do
      case "$1" in -p) port="${2#127.0.0.1:}"; port="${port%%:*}"; shift 2 ;; *) shift ;; esac
    done
    if busy "$port"; then echo "bind(descriptor:ptr:bytes:): Address already in use (errno: 48)" >&2; exit 1; fi
    echo "$port" > "$d/port"; echo running > "$d/state" ;;
  start)
    if busy "$(cat "$d/port")"; then echo "bind(descriptor:ptr:bytes:): Address already in use (errno: 48)" >&2; exit 1; fi
    echo running > "$d/state" ;;
  stop) [ -f "$d/state" ] && echo stopped > "$d/state"; exit 0 ;;
  rm) rm -f "$d/state" "$d/port" ;;
  exec) [ "$(cat "$d/state" 2>/dev/null)" = running ] ;;
  logs) exit 0 ;;
esac
`

type env struct {
	fake, state string
}

func newEnv(t *testing.T) env {
	t.Helper()
	root := t.TempDir()
	e := env{fake: filepath.Join(root, "fake"), state: filepath.Join(root, "state")}
	bin := filepath.Join(root, "bin")
	for _, d := range []string{e.fake, e.state, bin} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "container"), []byte(fakeContainer), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_DIR", e.fake)
	t.Setenv("XDG_STATE_HOME", e.state)
	t.Setenv("GATEON_PG_PORT", "")
	t.Setenv("GATEON_PG_TIMEOUT", "3")
	return e
}

func (e env) run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	script, err := filepath.Abs("../dev-postgres.sh")
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("bash", append([]string{script}, args...)...).CombinedOutput()
	return string(out), err
}

// occupy holds port the way a local Postgres would, or reports that something
// already holds it, which is the same thing for these tests.
func occupy(t *testing.T, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("cannot listen on %d: %v", port, err)
		}
		return // already held by something else
	}
	t.Cleanup(func() { _ = ln.Close() })
}

func (e env) publishedPort(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.fake, "port"))
	if err != nil {
		t.Fatalf("no container was created: %v", err)
	}
	return strings.TrimSpace(string(b))
}

// TestNewContainerAvoidsATakenPort is the reported failure: something already
// listens on the default port. The container must land on a free port, and
// the DSN the gateway is given must name that port, not the default.
func TestNewContainerAvoidsATakenPort(t *testing.T) {
	e := newEnv(t)
	occupy(t, defaultPort)

	if out, err := e.run(t, "up"); err != nil {
		t.Fatalf("up failed with the default port taken: %v\n%s", err, out)
	}
	port := e.publishedPort(t)
	if port == strconv.Itoa(defaultPort) {
		t.Fatalf("container published on the taken port %s", port)
	}
	dsn, err := e.run(t, "dsn")
	if err != nil || !strings.Contains(dsn, "127.0.0.1:"+port+"/") {
		t.Fatalf("dsn = %q (err %v), want port %s", dsn, err, port)
	}
}

// TestStoppedContainerOnATakenPortSaysWhatToDo: an existing container cannot
// move ports, so `up` must refuse with the port and the fix, not the CLI's
// bare bind() errno.
func TestStoppedContainerOnATakenPortSaysWhatToDo(t *testing.T) {
	e := newEnv(t)
	if out, err := e.run(t, "up"); err != nil {
		t.Fatalf("first up: %v\n%s", err, out)
	}
	port, _ := strconv.Atoi(e.publishedPort(t))
	if out, err := e.run(t, "down"); err != nil {
		t.Fatalf("down: %v\n%s", err, out)
	}
	occupy(t, port)

	out, err := e.run(t, "up")
	if err == nil {
		t.Fatalf("up started a container whose port is taken:\n%s", out)
	}
	for _, want := range []string{"port " + strconv.Itoa(port), "destroy"} {
		if !strings.Contains(out, want) {
			t.Errorf("error does not mention %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "errno") {
		t.Errorf("error is the CLI's bind failure, not the script's:\n%s", out)
	}
}

// TestExplicitPortIsNotSilentlyReplaced: a port the developer asked for is
// either used or refused, never swapped for another.
func TestExplicitPortIsNotSilentlyReplaced(t *testing.T) {
	e := newEnv(t)
	occupy(t, defaultPort+7)
	t.Setenv("GATEON_PG_PORT", strconv.Itoa(defaultPort+7))

	out, err := e.run(t, "up")
	if err == nil || !strings.Contains(out, "GATEON_PG_PORT") {
		t.Fatalf("up with a taken GATEON_PG_PORT: err=%v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(e.fake, "port")); statErr == nil {
		t.Fatal("a container was created despite the refusal")
	}
}

// TestDestroyForgetsThePort: after destroy, a new container picks again
// rather than reusing a port remembered from the old one.
func TestDestroyForgetsThePort(t *testing.T) {
	e := newEnv(t)
	if out, err := e.run(t, "up"); err != nil {
		t.Fatalf("up: %v\n%s", err, out)
	}
	if out, err := e.run(t, "destroy"); err != nil {
		t.Fatalf("destroy: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(e.state, "gateon", "gateon-dev-pg.port")); !os.IsNotExist(err) {
		t.Fatalf("port file survived destroy: %v", err)
	}
}
