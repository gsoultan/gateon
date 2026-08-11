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
#   GATEON_PG_PORT      host port               (default: 55432)
#   GATEON_PG_USER      role                    (default: gateon)
#   GATEON_PG_PASSWORD  password                (default: gateon)
#   GATEON_PG_DB        database                (default: gateon)
#   GATEON_PG_TIMEOUT   seconds to wait on up   (default: 90)
set -euo pipefail

PG_NAME="${GATEON_PG_NAME:-gateon-dev-pg}"
PG_IMAGE="${GATEON_PG_IMAGE:-postgres:18-alpine}"
PG_PORT="${GATEON_PG_PORT:-55432}"
PG_USER="${GATEON_PG_USER:-gateon}"
PG_PASSWORD="${GATEON_PG_PASSWORD:-gateon}"
PG_DB="${GATEON_PG_DB:-gateon}"
PG_TIMEOUT="${GATEON_PG_TIMEOUT:-90}"

# The port is published on 127.0.0.1 rather than 0.0.0.0 deliberately. These are
# throwaway credentials in a script, and binding them to every interface would
# put a trivially-guessable database on whatever network the laptop is on.
PG_HOST="127.0.0.1"

# Progress goes to stderr so `dsn` can be captured: DSN=$(dev-postgres.sh dsn).
say() { printf '==> %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

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
      say "starting existing container '${PG_NAME}'"
      container start "${PG_NAME}" >/dev/null
      ;;
    absent)
      say "creating '${PG_NAME}' from ${PG_IMAGE}"
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
    return 0
  fi
  say "deleting '${PG_NAME}' and all data in it"
  container stop "${PG_NAME}" >/dev/null 2>&1 || true
  container rm "${PG_NAME}" >/dev/null
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
    sed -n '4,29p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    ;;
  *) die "unknown command '${1}' (try -h)" ;;
esac
