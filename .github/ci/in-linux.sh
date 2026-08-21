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

args=(
    run --rm
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
