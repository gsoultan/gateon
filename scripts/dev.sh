#!/usr/bin/env bash
# Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
# SPDX-License-Identifier: MIT
#
# dev.sh — run gateon locally against the sample config in dev/.
#
# It starts PostgreSQL in an Apple container, builds the gateway, starts three
# throwaway upstream backends for the sample services to point at, seeds dev
# accounts so the dashboard is usable immediately, and boots gateon with every
# config file wired up. Local state lives under dev/.data/; gateon and the
# backends are torn down on exit, Postgres keeps running.
#
#   Dashboard : http://localhost:8080   (login: admin / admin; the next free
#               port if 8080 is taken, or GATEON_MANAGEMENT_PORT)
#   Proxy     : http://localhost:8000   (the sample routes)
#
# The dev accounts are admin/admin, operator/operator and viewer/viewer. Those
# passwords exist only here: the password policy refuses them on every API, and
# dev/seed writes them only into a SQLite file under dev/.data or a Postgres on
# a loopback address. The dashboard listens on 127.0.0.1 only.
#
# Usage:
#   scripts/dev.sh              # Postgres in an Apple container (default)
#   scripts/dev.sh --sqlite     # SQLite under dev/.data instead, no container
#   scripts/dev.sh --ui         # rebuild the dashboard UI first, then run
#   scripts/dev.sh --clean      # start from an empty database
#   scripts/dev.sh -h           # help
#   make dev / make dev-sqlite  # the same, from make
#
# Postgres is managed by scripts/dev-postgres.sh (Apple's `container` CLI,
# macOS 15+ on Apple silicon). The container is left running on exit so the
# next run is instant; stop it with 'scripts/dev-postgres.sh down' or throw the
# data away with 'destroy'. With --clean it is destroyed and recreated, which is
# the only way to get a genuinely empty schema — dropping dev/.data does nothing
# to a database that does not live there.
set -euo pipefail

# ---- locate the repo and toolchain -----------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

GO="$(command -v go || true)"
[ -z "${GO}" ] && [ -x /opt/homebrew/bin/go ] && GO=/opt/homebrew/bin/go

BUILD_UI=false
CLEAN=false
POSTGRES=true
for arg in "$@"; do
  case "${arg}" in
    --ui) BUILD_UI=true ;;
    --clean) CLEAN=true ;;
    --sqlite) POSTGRES=false ;;
    --postgres|--pg) POSTGRES=true ;; # the default; kept so old habits work
    -h|--help)
      sed -n '4,35p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "error: unknown flag '${arg}' (try -h)" >&2; exit 1 ;;
  esac
done

# ---- config: everything the run needs, in one place ------------------------
CONFIG_DIR="${REPO_ROOT}/dev"
DATA_DIR="${CONFIG_DIR}/.data"
DB_PATH="${DATA_DIR}/gateon-dev.db"
TRACE_DIR="${DATA_DIR}/trace"
PASETO_SECRET="dev-secret-please-change-me-0123" # must match dev/global.json
GATEON_BIN="${DATA_DIR}/gateon"
BACKEND_BIN="${DATA_DIR}/devbackend"
PG_SCRIPT="${SCRIPT_DIR}/dev-postgres.sh"

# The database everything points at, and the config file that names it. On
# SQLite (--sqlite) these are the checked-in defaults; Postgres replaces both. One
# variable rather than a branch at each use site: gateon derives the WAF rule
# store, the audit log, path stats and auth from this single URL
# (db.AuthDatabaseURL), so a second copy that drifted would split the gateway
# across two databases without failing.
DB_URL="${DB_PATH}"
GLOBAL_CONFIG="${CONFIG_DIR}/global.json"
DB_LABEL="SQLite  ${DB_PATH}"

# Backend upstreams the sample services in dev/services.json point at.
WHOAMI_ADDR="127.0.0.1:9001"
API_ADDR="127.0.0.1:9002"
CANARY_ADDR="127.0.0.1:9003"

BG_PIDS=()
cleanup() {
  echo
  echo "==> stopping gateon and dev backends"
  for pid in "${BG_PIDS[@]:-}"; do
    [ -n "${pid}" ] && kill "${pid}" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

# ---- preflight: every prerequisite, checked before any work starts ---------
# A run that fails on the fifth missing tool, one at a time, after minutes of
# building, is worse than one that lists all of them in the first second. So
# everything that cannot be installed from here is checked first and reported
# together; everything that can is installed into dev/.tools, which goes
# first on PATH for the rest of the run.
TOOLS_DIR="${CONFIG_DIR}/.tools" # outside .data, so --clean keeps it
missing=""
need() { missing="${missing}
  - $1: $2"; }
[ -n "${GO}" ] || need go "brew install go"
BUN="$(command -v bun || true)"
[ -n "${BUN}" ] || need bun "brew install oven-sh/bun/bun"
if ${POSTGRES}; then
  command -v container >/dev/null 2>&1 ||
    need container "brew install container (macOS 15+ on Apple silicon), or run with --sqlite"
  command -v jq >/dev/null 2>&1 || need jq "brew install jq, or run with --sqlite"
fi
if [ -n "${missing}" ]; then
  echo "error: dev.sh needs these, and found none of them on PATH:${missing}" >&2
  exit 1
fi
mkdir -p "${TOOLS_DIR}"
export PATH="${TOOLS_DIR}:${PATH}"

# Some JavaScript tools (protoc-gen-es among them) start with
# '#!/usr/bin/env node'. A machine with only bun has no node, and bun runs
# those scripts unchanged, so a two-line node that hands off to bun is enough.
if ! command -v node >/dev/null 2>&1; then
  printf '#!/bin/sh\nexec "%s" "$@"\n' "${BUN}" > "${TOOLS_DIR}/node"
  chmod +x "${TOOLS_DIR}/node"
  echo "==> no node found; using bun as node (${TOOLS_DIR}/node)"
fi

# The dashboard defaults to 8080, which plenty of other tools also want. Take
# the first free port from there rather than fail on bind; an explicit
# GATEON_MANAGEMENT_PORT is used as given, since asking for a port means it.
port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
if [ -z "${GATEON_MANAGEMENT_PORT:-}" ]; then
  mgmt=8080
  while port_busy "${mgmt}"; do
    mgmt=$((mgmt + 1))
    if [ "${mgmt}" -ge 8130 ]; then
      echo "error: ports 8080-8129 are all in use; set GATEON_MANAGEMENT_PORT" >&2
      exit 1
    fi
  done
  [ "${mgmt}" = 8080 ] || echo "==> port 8080 is in use; the dashboard will use ${mgmt}"
  export GATEON_MANAGEMENT_PORT="${mgmt}"
fi
DASHBOARD_URL="http://localhost:${GATEON_MANAGEMENT_PORT}"

# The container system has to be running before Postgres can start, and
# starting it is safe to do on the user's behalf.
if ${POSTGRES} && ! container ls >/dev/null 2>&1; then
  echo "==> starting the container system (container system start)"
  container system start
fi

if ${CLEAN}; then
  echo "==> --clean: removing ${DATA_DIR}"
  rm -rf "${DATA_DIR}"
  # A Postgres database does not live in dev/.data, so --clean has to say so to
  # the thing that owns it. Without this, --clean on --postgres would look like
  # it reset the world and leave every row in place.
  if ${POSTGRES}; then
    "${PG_SCRIPT}" destroy
  fi
fi
mkdir -p "${DATA_DIR}" "${TRACE_DIR}"

# ---- database --------------------------------------------------------------
if ${POSTGRES}; then
  command -v jq >/dev/null 2>&1 || {
    echo "error: Postgres mode needs 'jq' to write the dev config (brew install jq), or run with --sqlite" >&2
    exit 1
  }
  "${PG_SCRIPT}" up
  DB_URL="$("${PG_SCRIPT}" dsn)"

  # dev/global.json is checked in and points at SQLite. Rather than edit it in
  # place — which would show up in every developer's git status and eventually
  # get committed — the Postgres run gets a generated copy under dev/.data. Only
  # auth.database_url differs, so the two modes stay honestly comparable.
  GLOBAL_CONFIG="${DATA_DIR}/global.postgres.json"
  jq --arg dsn "${DB_URL}" '.auth.database_url = $dsn' \
    "${CONFIG_DIR}/global.json" > "${GLOBAL_CONFIG}"
  DB_LABEL="Postgres  $("${PG_SCRIPT}" status | awk '/^address/ {print $2}')  (container: ${GATEON_PG_NAME:-gateon-dev-pg})"
fi

# ---- build -----------------------------------------------------------------
# The dashboard is embedded from internal/ui/dist. Rebuild it on --ui, or when
# it is missing entirely (a fresh checkout), so the go:embed has something to
# read; otherwise reuse whatever is embedded and skip the slow UI build.
if ${BUILD_UI} || [ ! -d "${REPO_ROOT}/internal/ui/dist" ]; then
  echo "==> building dashboard UI"
  # Install first: a fresh checkout, or one whose lockfile moved since the
  # last install, has no or stale node_modules, and the build then fails on a
  # missing tsc. With nothing to change this takes well under a second.
  ( cd "${REPO_ROOT}/ui" && bun install --frozen-lockfile && bun run build )
  "${GO}" run "${REPO_ROOT}/scripts/sync_assets.go"
fi

# The gRPC/Connect stubs are generated, not committed (.gitignore), so a fresh
# checkout cannot compile until they exist. Generate them once rather than fail
# on "no required module provides package .../proto/gateon/v1".
if ! compgen -G "${REPO_ROOT}/proto/gateon/v1/*.pb.go" >/dev/null; then
  echo "==> generating gRPC code (make proto)"
  # buf and the Go plugins are pinned as tools in go.mod, so build those exact
  # versions here rather than ask for an install that might not match. The
  # first run takes a minute; later runs reuse dev/.tools.
  for tool in github.com/bufbuild/buf/cmd/buf \
    google.golang.org/protobuf/cmd/protoc-gen-go \
    google.golang.org/grpc/cmd/protoc-gen-go-grpc \
    connectrpc.com/connect/cmd/protoc-gen-connect-go; do
    [ -x "${TOOLS_DIR}/${tool##*/}" ] || "${GO}" build -o "${TOOLS_DIR}/${tool##*/}" "${tool}"
  done
  # buf also generates the dashboard's TypeScript client with a plugin that
  # lives in ui/node_modules.
  [ -x "${REPO_ROOT}/ui/node_modules/.bin/protoc-gen-es" ] || ( cd "${REPO_ROOT}/ui" && bun install --frozen-lockfile )
  ( cd "${REPO_ROOT}" && ./scripts/buf-generate.sh >/dev/null )
fi

echo "==> building gateon"
"${GO}" build -o "${GATEON_BIN}" ./cmd/gateon

echo "==> building dev backend"
"${GO}" build -o "${BACKEND_BIN}" ./dev/backend

# ---- sample upstreams ------------------------------------------------------
echo "==> starting sample backends"
"${BACKEND_BIN}" -name whoami -addr "${WHOAMI_ADDR}" & BG_PIDS+=("$!")
"${BACKEND_BIN}" -name api -addr "${API_ADDR}" & BG_PIDS+=("$!")
"${BACKEND_BIN}" -name canary -addr "${CANARY_ADDR}" & BG_PIDS+=("$!")

wait_for() { # host:port
  local hp="$1" host="${1%%:*}" port="${1##*:}" i
  for i in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/${host}/${port}") 2>/dev/null; then exec 3>&- 3<&-; return 0; fi
    sleep 0.1
  done
  echo "error: ${hp} did not come up" >&2; return 1
}
wait_for "${WHOAMI_ADDR}"
wait_for "${API_ADDR}"
wait_for "${CANARY_ADDR}"

# ---- seed the dev accounts -------------------------------------------------
# admin/admin, operator/operator, viewer/viewer. Set GATEON_DEV_PASSWORD to give
# all three one password of your own instead.
echo "==> seeding dev accounts (admin/operator/viewer)"
GATEON_DEV_DB="${DB_URL}" GATEON_DEV_PASETO="${PASETO_SECRET}" \
  "${GO}" run ./dev/seed -db "${DB_URL}" -secret "${PASETO_SECRET}"

# ---- run gateon ------------------------------------------------------------
if [ -n "${GATEON_DEV_PASSWORD:-}" ]; then
  LOGIN_HINT="admin / \$GATEON_DEV_PASSWORD"
else
  LOGIN_HINT="admin / admin   — dev only"
fi

# Ctrl-C stops gateon but deliberately leaves Postgres running, so say what that
# means and how to undo it. A container still running after the script exited is
# only a surprise if nothing mentioned it.
PG_HINT=""
if ${POSTGRES}; then
  PG_HINT="
  Postgres keeps running after Ctrl-C (next start is instant):
    scripts/dev-postgres.sh psql        # a shell on the dev database
    scripts/dev-postgres.sh down        # stop it, keep the data
    scripts/dev-postgres.sh destroy     # throw the data away
"
fi

cat <<BANNER

────────────────────────────────────────────────────────────────────
  gateon dev is starting

  Dashboard   ${DASHBOARD_URL}     (login: ${LOGIN_HINT})
  Proxy       http://localhost:8000
  Database    ${DB_LABEL}

  Sample routes (dev/routes.json):
    host-route    Host(whoami.localhost)   -> whoami-service   [security headers, compress, request id]
    api-route     PathPrefix(/api)         -> api-service      [waf, ratelimit, inflight, circuit breaker, strip /api]
    canary-route  PathPrefix(/canary)      -> canary-service   [90% whoami / 10% canary, retry, strip /canary]
    web-route     PathPrefix(/)            -> whoami-service   [dev-headers, cors]

  Try it:
    curl http://localhost:8000/                         # whoami backend
    curl http://whoami.localhost:8000/                  # host-based route
    curl http://localhost:8000/api/anything             # api backend, /api stripped
    for i in \$(seq 20); do curl -s http://localhost:8000/canary/ | jq -r .backend; done | sort | uniq -c
    curl 'http://localhost:8000/api/x?id=1%27+OR+1=1'   # WAF blocks this (403)

  (WAF blocks from 127.0.0.1 are not recorded as Security Hub threats —
   loopback is trusted; drive traffic from another host to populate it.)

  Ctrl-C to stop. State is under dev/.data/ (use --clean to reset).
${PG_HINT}────────────────────────────────────────────────────────────────────

BANNER

export GATEON_PROFILE=standard
export GATEON_CONFIG_DIR="${CONFIG_DIR}"
export GLOBAL_CONFIG_FILE="${GLOBAL_CONFIG}"
export ROUTES_FILE="${CONFIG_DIR}/routes.json"
export SERVICES_FILE="${CONFIG_DIR}/services.json"
export ENTRYPOINTS_FILE="${CONFIG_DIR}/entrypoints.json"
export MIDDLEWARES_FILE="${CONFIG_DIR}/middlewares.json"
export TLS_OPTIONS_FILE="${CONFIG_DIR}/tls_options.json"
export GATEON_TRACE_DIR="${TRACE_DIR}"

# Run gateon in the background and wait on it, rather than exec or a plain
# foreground call. `wait` is interruptible, so a Ctrl-C (or a signal delivered
# only to this script, not the whole group) runs the trap immediately, which
# tears down gateon and both backends together. Adding gateon's PID to the
# cleanup list is what lets the trap stop it even when the signal never reached
# it directly.
"${GATEON_BIN}" &
GATEON_PID=$!
BG_PIDS+=("${GATEON_PID}")
wait "${GATEON_PID}"
