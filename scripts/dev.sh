#!/usr/bin/env bash
# Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
# SPDX-License-Identifier: MIT
#
# dev.sh — run gateon locally against the sample config in dev/.
#
# It builds the gateway, starts two throwaway upstream backends for the sample
# services to point at, seeds a dev admin so the dashboard is usable immediately,
# and boots gateon with every config file wired up. Everything it creates lives
# under dev/.data/ and is torn down on exit.
#
#   Dashboard : http://localhost:8080   (login: admin / password123)
#   Proxy     : http://localhost:8000   (the sample routes)
#
# Usage:
#   scripts/dev.sh              # build (using embedded UI) and run, on SQLite
#   scripts/dev.sh --postgres   # run against Postgres in an Apple container
#   scripts/dev.sh --ui         # rebuild the dashboard UI first, then run
#   scripts/dev.sh --clean      # wipe dev/.data (fresh DB) before running
#   scripts/dev.sh -h           # help
#
# --postgres starts (or reuses) the database managed by scripts/dev-postgres.sh
# and points every store at it. The container is left running on exit so the next
# run is instant; stop it with 'scripts/dev-postgres.sh down' or throw the data
# away with 'destroy'. With --clean it is destroyed and recreated, which is the
# only way to get a genuinely empty schema — dropping dev/.data does nothing to a
# database that does not live there.
set -euo pipefail

# ---- locate the repo and toolchain -----------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

GO="$(command -v go || true)"
[ -z "${GO}" ] && [ -x /opt/homebrew/bin/go ] && GO=/opt/homebrew/bin/go
if [ -z "${GO}" ]; then
  echo "error: 'go' not found on PATH (and not at /opt/homebrew/bin/go)" >&2
  exit 1
fi

BUILD_UI=false
CLEAN=false
POSTGRES=false
for arg in "$@"; do
  case "${arg}" in
    --ui) BUILD_UI=true ;;
    --clean) CLEAN=true ;;
    --postgres|--pg) POSTGRES=true ;;
    -h|--help)
      sed -n '3,34p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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
# SQLite these are the checked-in defaults; --postgres replaces both. One
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

BG_PIDS=()
cleanup() {
  echo
  echo "==> stopping gateon and dev backends"
  for pid in "${BG_PIDS[@]:-}"; do
    [ -n "${pid}" ] && kill "${pid}" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

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
    echo "error: --postgres needs 'jq' to write the dev config (brew install jq)" >&2
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
  ( cd "${REPO_ROOT}/ui" && bun run build )
  "${GO}" run "${REPO_ROOT}/scripts/sync_assets.go"
fi

echo "==> building gateon"
"${GO}" build -o "${GATEON_BIN}" ./cmd/gateon

echo "==> building dev backend"
"${GO}" build -o "${BACKEND_BIN}" ./dev/backend

# ---- sample upstreams ------------------------------------------------------
echo "==> starting sample backends"
"${BACKEND_BIN}" -name whoami -addr "${WHOAMI_ADDR}" & BG_PIDS+=("$!")
"${BACKEND_BIN}" -name api -addr "${API_ADDR}" & BG_PIDS+=("$!")

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

# ---- seed the dev admin ----------------------------------------------------
echo "==> seeding dev accounts (admin/operator/viewer)"
GATEON_DEV_DB="${DB_URL}" GATEON_DEV_PASETO="${PASETO_SECRET}" \
  "${GO}" run ./dev/seed -db "${DB_URL}" -secret "${PASETO_SECRET}"

# ---- run gateon ------------------------------------------------------------
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

  Dashboard   http://localhost:8080     (login: admin / password123)
  Proxy       http://localhost:8000
  Database    ${DB_LABEL}

  Sample routes (dev/routes.json):
    web-route   PathPrefix(/)      -> whoami-service   [dev-headers, cors]
    api-route   PathPrefix(/api)   -> api-service      [waf, ratelimit, strip /api]

  Try it:
    curl http://localhost:8000/                       # whoami backend
    curl http://localhost:8000/api/anything           # api backend, /api stripped
    curl 'http://localhost:8000/api/x?id=1%27+OR+1=1' # WAF blocks this (403)

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
