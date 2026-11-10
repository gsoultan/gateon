#!/usr/bin/env bash
# Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
# SPDX-License-Identifier: MIT
#
# dev-postgres.sh — the local Postgres gateon develops against, run on Apple's
# `container` CLI.
#
# It owns one container and nothing else, so it is useful on its own and is also
# what `scripts/dev.sh --postgres` calls. Every command is idempotent: `up` on an
# already-running database waits for it to answer and exits, which is what makes
# it safe to put in front of anything.
#
# Commands:
#   up        create or start the database, wait until it accepts queries (default)
#   down      stop the container, keep the data
#   destroy   delete the container and everything in it
#   dsn       print the connection URL on stdout, nothing else
#   psql      open a psql shell inside the container
#   status    show what is running
#   logs      tail the Postgres log
#
# Overrides (all optional):
#   GATEON_PG_NAME      container name          (default: gateon-dev-pg)
#   GATEON_PG_IMAGE     image                   (default: postgres:18-alpine)
#   GATEON_PG_PORT      host port               (default: first free from 54329)
#   GATEON_PG_USER      role                    (default: gateon)
#   GATEON_PG_PASSWORD  password                (default: gateon)
#   GATEON_PG_DB        database                (default: gateon)
#   GATEON_PG_TIMEOUT   seconds to wait on up   (default: 90)
#
# Port: the database gets a port of its own, never a guess that might collide.
# A new container takes the first free port from 54329 up, and the port it got
# is remembered (under $XDG_STATE_HOME/gateon, ~/.local/state/gateon by
# default), so `dsn`, `status` and every later `up` use the same one. Set
# GATEON_PG_PORT to insist on a port; `up` then refuses if it is taken rather
# than picking another. A stopped container whose port something else has
# since taken cannot be moved (its port is fixed when it is created), so `up`
# names what holds the port and says how to recreate it.
set -euo pipefail

PG_NAME="${GATEON_PG_NAME:-gateon-dev-pg}"
PG_IMAGE="${GATEON_PG_IMAGE:-postgres:18-alpine}"
PG_PORT_DEFAULT=54329
PG_PORT_SEARCH=50 # how many ports above the default a new container may take
PG_USER="${GATEON_PG_USER:-gateon}"
PG_PASSWORD="${GATEON_PG_PASSWORD:-gateon}"
PG_DB="${GATEON_PG_DB:-gateon}"
PG_TIMEOUT="${GATEON_PG_TIMEOUT:-90}"

# The port is published on 127.0.0.1 rather than 0.0.0.0 deliberately. These are
# throwaway credentials in a script, and binding them to every interface would
# put a trivially-guessable database on whatever network the laptop is on.
PG_HOST="127.0.0.1"

# Where the port a container was created with is remembered. Not under dev/.data:
# `scripts/dev.sh --clean` wipes that directory while the container lives on, and
# a forgotten port would point the gateway at whatever holds the default.
PG_STATE_DIR="${XDG_STATE_HOME:-${HOME}/.local/state}/gateon"
PG_PORT_FILE="${PG_STATE_DIR}/${PG_NAME}.port"

# saved_port prints the port the container was created with, if it was recorded.
saved_port() {
  local p
  [ -r "${PG_PORT_FILE}" ] || return 1
  p="$(tr -dc '0-9' < "${PG_PORT_FILE}")"
  [ -n "${p}" ] || return 1
  printf '%s\n' "${p}"
}

# The port everything reads. A container made before ports were recorded was
# made on the default, which is what this falls back to.
PG_PORT="$(saved_port || printf '%s' "${GATEON_PG_PORT:-${PG_PORT_DEFAULT}}")"

# Progress goes to stderr so `dsn` can be captured: DSN=$(dev-postgres.sh dsn).
say() { printf '==> %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# port_in_use reports whether something accepts connections on PG_HOST:$1.
# Connecting, not binding, so it sees a listener on 0.0.0.0 as well as one on
# 127.0.0.1, which is the case that collides with a published port.
port_in_use() {
  (exec 3<>"/dev/tcp/${PG_HOST}/$1") 2>/dev/null
}

# port_holder names the process listening on $1, or says it could not tell.
port_holder() {
  local who=""
  if command -v lsof >/dev/null 2>&1; then
    who="$(lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | awk 'NR > 1 {print $1 " (pid " $2 ")"}' | sort -u | paste -sd, - || true)"
  fi
  printf '%s\n' "${who:-an unknown process}"
}

# pick_port prints the port a new container should publish on.
pick_port() {
  local p
  if [ -n "${GATEON_PG_PORT:-}" ]; then
    port_in_use "${GATEON_PG_PORT}" && die "GATEON_PG_PORT=${GATEON_PG_PORT} is already in use by $(port_holder "${GATEON_PG_PORT}").
       Unset GATEON_PG_PORT to let the script pick a free port, or choose another."
    printf '%s\n' "${GATEON_PG_PORT}"
    return 0
  fi
  for p in $(seq "${PG_PORT_DEFAULT}" $((PG_PORT_DEFAULT + PG_PORT_SEARCH))); do
    if ! port_in_use "${p}"; then
      printf '%s\n' "${p}"
      return 0
    fi
  done
  die "no free port between ${PG_PORT_DEFAULT} and $((PG_PORT_DEFAULT + PG_PORT_SEARCH)); set GATEON_PG_PORT"
}

save_port() {
  mkdir -p "${PG_STATE_DIR}"
  printf '%s\n' "$1" > "${PG_PORT_FILE}"
}

dsn() {
  printf 'postgres://%s:%s@%s:%s/%s?sslmode=disable\n' \
    "${PG_USER}" "${PG_PASSWORD}" "${PG_HOST}" "${PG_PORT}" "${PG_DB}"
}

require_container_cli() {
  command -v container >/dev/null 2>&1 || die \
    "Apple's 'container' CLI is not on PATH. Install it with 'brew install container'
       (it needs macOS 15+ on Apple silicon), then run 'container system start'."

  command -v jq >/dev/null 2>&1 || die \
    "'jq' is required to read container state. Install it with 'brew install jq'."

  # `container ls` is the cheapest call that fails when the helper services are
  # down, and that failure is worth catching here: every later command would
  # otherwise fail one at a time with the same unhelpful message.
  if ! container ls >/dev/null 2>&1; then
    die "the container system is not running — start it with 'container system start'"
  fi
}

# container_state prints running | stopped | absent.
#
# It reads `container inspect` rather than the columns of `container ls`, which
# looks simpler and is wrong: a stopped container leaves the IP column empty, so
# every field after it shifts left and a positional read of STATE returns an IP
# address for running containers and a CPU count for stopped ones.
container_state() {
  local json
  if ! json="$(container inspect "${PG_NAME}" 2>/dev/null)"; then
    printf 'absent\n'
    return 0
  fi
  local state
  state="$(printf '%s' "${json}" | jq -r '.[0].status.state // .[0].status // "unknown"' 2>/dev/null)"
  case "${state}" in
    running) printf 'running\n' ;;
    "" | unknown | null) printf 'absent\n' ;;
    *) printf 'stopped\n' ;;
  esac
}

# ready reports whether Postgres is answering. pg_isready is run inside the
# container rather than from the host so this works without a host psql install,
# which most machines do not have.
ready() {
  container exec "${PG_NAME}" pg_isready -U "${PG_USER}" -d "${PG_DB}" >/dev/null 2>&1
}

wait_ready() {
  local waited=0
  say "waiting for Postgres to accept queries (timeout ${PG_TIMEOUT}s)"
  while [ "${waited}" -lt "${PG_TIMEOUT}" ]; do
    if ready; then
      say "Postgres is ready on ${PG_HOST}:${PG_PORT}"
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done

  # A timeout prints the log rather than just the elapsed seconds. The usual
  # cause is a port already taken or an incompatible data directory left by an
  # earlier image, and both say so plainly in the Postgres log.
  printf 'error: Postgres did not become ready within %ss. Last log lines:\n' "${PG_TIMEOUT}" >&2
  container logs "${PG_NAME}" 2>&1 | tail -30 >&2
  return 1
}

up() {
  require_container_cli

  case "$(container_state)" in
    running)
      say "container '${PG_NAME}' is already running"
      ;;
    stopped)
      # Checked before `container start`, whose own failure is a bind() errno
      # that names neither the port nor what holds it.
      if port_in_use "${PG_PORT}"; then
        die "port ${PG_PORT}, which '${PG_NAME}' was created on, is now used by $(port_holder "${PG_PORT}").
       A container's port cannot be changed, so either stop that process, or recreate
       the dev database on a free port (this deletes its data):
         scripts/dev-postgres.sh destroy && scripts/dev-postgres.sh up"
      fi
      say "starting existing container '${PG_NAME}' on port ${PG_PORT}"
      container start "${PG_NAME}" >/dev/null
      ;;
    absent)
      PG_PORT="$(pick_port)"
      say "creating '${PG_NAME}' from ${PG_IMAGE} on port ${PG_PORT}"
      # No volume mount. The container's own filesystem is the persistence, and
      # it survives stop/start — mounting a macOS directory into
      # /var/lib/postgresql/data instead trips the ownership checks initdb makes
      # over virtiofs, which fails at first start with an error that reads like a
      # Postgres bug rather than a mount problem. `destroy` is how data goes.
      container run -d \
        --name "${PG_NAME}" \
        -e POSTGRES_USER="${PG_USER}" \
        -e POSTGRES_PASSWORD="${PG_PASSWORD}" \
        -e POSTGRES_DB="${PG_DB}" \
        -p "${PG_HOST}:${PG_PORT}:5432" \
        "${PG_IMAGE}" >/dev/null
      save_port "${PG_PORT}"
      ;;
  esac

  wait_ready
}

down() {
  require_container_cli
  if [ "$(container_state)" = "absent" ]; then
    say "container '${PG_NAME}' does not exist"
    return 0
  fi
  say "stopping '${PG_NAME}' (data is kept; use 'destroy' to remove it)"
  container stop "${PG_NAME}" >/dev/null 2>&1 || true
}

destroy() {
  require_container_cli
  if [ "$(container_state)" = "absent" ]; then
    say "container '${PG_NAME}' does not exist"
    rm -f "${PG_PORT_FILE}"
    return 0
  fi
  say "deleting '${PG_NAME}' and all data in it"
  container stop "${PG_NAME}" >/dev/null 2>&1 || true
  container rm "${PG_NAME}" >/dev/null
  rm -f "${PG_PORT_FILE}"
}

status() {
  require_container_cli
  local state
  state="$(container_state)"
  printf 'container  %s\n' "${PG_NAME}"
  printf 'image      %s\n' "${PG_IMAGE}"
  printf 'state      %s\n' "${state}"
  if [ "${state}" = "running" ]; then
    printf 'address    %s:%s\n' "${PG_HOST}" "${PG_PORT}"
    printf 'ready      %s\n' "$(ready && echo yes || echo no)"
    printf 'dsn        %s\n' "$(dsn)"
  fi
}

case "${1:-up}" in
  up)      up ;;
  down)    down ;;
  destroy) destroy ;;
  dsn)     dsn ;;
  status)  status ;;
  logs)    require_container_cli; container logs "${PG_NAME}" ;;
  psql)
    require_container_cli
    [ "$(container_state)" = "running" ] || die "container '${PG_NAME}' is not running (try: $0 up)"
    shift || true
    container exec -it "${PG_NAME}" psql -U "${PG_USER}" -d "${PG_DB}" "$@"
    ;;
  -h|--help|help)
    sed -n '4,38p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    ;;
  *) die "unknown command '${1}' (try -h)" ;;
esac
