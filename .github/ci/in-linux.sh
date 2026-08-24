#!/usr/bin/env bash
# Run one CI step inside the Linux container described by .github/ci/Dockerfile.ci.
#
# The runner is an Apple-silicon Mac and several steps are Linux-only (the eBPF
# toolchain, bpf2go, and internal/ebpf/manager_linux.go). Wrapping each step
# rather than running the whole job as one `container run` keeps the steps
# separate in the Actions UI, so a failure still points at a named step instead
# of at a hundred-line script.
#
# Two mounts carry state that would otherwise be lost between steps:
#   /src       the checkout, so generated artifacts (buf, bpf2go, ui/dist)
#              produced by one step are visible to the next
#   /go        GOPATH, so `go install tool` binaries and the module cache
#              survive. It lives under RUNNER_TEMP rather than in the image so
#              it is not baked in, and on the host rather than in a GitHub cache
#              because this runner keeps its disk between jobs -- uploading a
#              multi-gigabyte module cache to GitHub is slower than rebuilding.
#   /root/.cache  GOCACHE. Without it every step recompiles the whole module
#              from nothing, because each step is its own `container run --rm`.
#
# Note that a persistent GOCACHE also persists Go's *test* result cache, which
# will report `ok (cached)` for a suite it never executed. Steps that run tests
# pass -count=1 for that reason; see the Test step in ci.yml.
set -euo pipefail

if [ "$#" -eq 0 ]; then
    echo "usage: $0 <command...>" >&2
    exit 2
fi

CACHE_ROOT="${RUNNER_TEMP:-/tmp}/gateon-ci"
mkdir -p "$CACHE_ROOT/go" "$CACHE_ROOT/build"

# Apple `container` defaults to 1 GB and 4 CPUs, which is not enough to build
# this module: `make lint-new` builds golangci-lint from source and was killed
# by the OOM reaper after fifteen minutes, reported only as `signal: killed`.
# The host has 24 GB and 15 CPUs; these leave room for the Postgres container
# and for the machine to stay usable while CI runs on it.
CI_MEMORY="${CI_MEMORY:-10g}"
CI_CPUS="${CI_CPUS:-8}"

# The container resolves DNS through the gateway at 192.168.64.1, which has
# been seen to answer "server misbehaving" mid-run and fail a whole job on
# `lookup proxy.golang.org`. A public resolver is used instead: nothing here
# resolves a name that is only meaningful on this LAN -- the one such name,
# the Postgres container's address, is passed in already resolved.
CI_DNS="${CI_DNS:-1.1.1.1}"

args=(
    run --rm
    --memory "$CI_MEMORY" --cpus "$CI_CPUS"
    --dns "$CI_DNS"
    -v "$PWD:/src" -w /src
    -v "$CACHE_ROOT/go:/go"
    -v "$CACHE_ROOT/build:/root/.cache"
)

# Forward only the variables a step actually set. A step that does not need
# Postgres should not inherit a pointer to a database that is not running, and
# GITHUB_TOKEN should reach the release job and nothing else -- every other step
# here runs untrusted-ish tooling over the tree.
for var in GATEON_TEST_POSTGRES_DSN GITHUB_TOKEN GORELEASER_CURRENT_TAG; do
    if [ -n "${!var:-}" ]; then
        args+=(-e "$var=${!var}")
    fi
done

exec container "${args[@]}" "${CI_IMAGE:-gateon-ci}" \
    bash -euo pipefail -c "$*"
