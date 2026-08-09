#!/usr/bin/env bash
# Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
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
#   scripts/dev.sh            # build (using embedded UI) and run
#   scripts/dev.sh --ui       # rebuild the dashboard UI first, then run
#   scripts/dev.sh --clean    # wipe dev/.data (fresh DB) before running
#   scripts/dev.sh -h         # help
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
for arg in "$@"; do
  case "${arg}" in
    --ui) BUILD_UI=true ;;
    --clean) CLEAN=true ;;
    -h|--help)
      sed -n '3,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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
fi
mkdir -p "${DATA_DIR}" "${TRACE_DIR}"

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
GATEON_DEV_DB="${DB_PATH}" GATEON_DEV_PASETO="${PASETO_SECRET}" \
  "${GO}" run ./dev/seed -db "${DB_PATH}" -secret "${PASETO_SECRET}"

# ---- run gateon ------------------------------------------------------------
cat <<BANNER

────────────────────────────────────────────────────────────────────
  gateon dev is starting

  Dashboard   http://localhost:8080     (login: admin / password123)
  Proxy       http://localhost:8000

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
────────────────────────────────────────────────────────────────────

BANNER

export GATEON_PROFILE=standard
export GATEON_CONFIG_DIR="${CONFIG_DIR}"
export GLOBAL_CONFIG_FILE="${CONFIG_DIR}/global.json"
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
