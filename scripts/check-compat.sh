#!/usr/bin/env bash
# Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
# SPDX-License-Identifier: MIT
#
# check-compat: hold this tree to the compatibility rule (ADR 0102).
#
# The rule is that the last release can be upgraded to this build and rolled
# back again: this build starts on the configuration and the database the last
# release wrote, and the last release starts again on what this build left.
# A self-upgrade rolls back by putting the old binary back, so a change that
# breaks the second half breaks every rollback after it ships.
#
# This downloads the last release's own tarball, checks it against that
# release's checksums.txt, and runs the specs in tests/e2e that start the two
# binaries as real processes on one state, on SQLite and on PostgreSQL.
#
# Nothing here is allowed to skip. A spec that finds no previous binary or no
# PostgreSQL fails, because a gate that passes without running reports a rule
# it did not check.
#
#   GATEON_COMPAT_VERSION     the release to compare against (default: the latest)
#   GATEON_COMPAT_PREVIOUS    a previous binary already on disk; skips the download
#   GATEON_TEST_POSTGRES_DSN  a PostgreSQL the specs may create databases in (required)
set -euo pipefail

repo="gsoultan/gateon"
root="$(cd "$(dirname "$0")/.." && pwd)"

if [ "$(go env GOOS)" != "linux" ]; then
  echo "check-compat: releases are built for linux; run this on linux, or set GATEON_COMPAT_PREVIOUS to a binary for this machine" >&2
  [ -n "${GATEON_COMPAT_PREVIOUS:-}" ] || exit 1
fi

if [ -z "${GATEON_TEST_POSTGRES_DSN:-}" ]; then
  echo "check-compat: GATEON_TEST_POSTGRES_DSN is not set, so PostgreSQL would go unchecked." >&2
  echo "              \`make dev\` starts one; CI uses postgres://gateon:gateon@localhost:5432/gateon_test?sslmode=disable" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

previous="${GATEON_COMPAT_PREVIOUS:-}"
if [ -z "$previous" ]; then
  tag="${GATEON_COMPAT_VERSION:-}"
  if [ -z "$tag" ]; then
    # The redirect of /releases/latest names the tag, with no API quota to run out of.
    tag="$(curl -sSfI "https://github.com/$repo/releases/latest" | tr -d '\r' | sed -n 's|^[Ll]ocation: .*/releases/tag/||p')"
  fi
  if [ -z "$tag" ]; then
    echo "check-compat: could not find the latest release of $repo" >&2
    exit 1
  fi
  version="${tag#v}"
  arch="$(go env GOARCH)"
  tarball="gateon_${version}_linux_${arch}.tar.gz"
  base="https://github.com/$repo/releases/download/$tag"
  echo "check-compat: comparing against $tag ($tarball)"
  curl -sSfL -o "$work/$tarball" "$base/$tarball"
  curl -sSfL -o "$work/checksums.txt" "$base/checksums.txt"
  if ! (cd "$work" && grep " $tarball\$" checksums.txt | sha256sum -c - >/dev/null); then
    echo "check-compat: $tarball does not match $tag's checksums.txt" >&2
    exit 1
  fi
  mkdir "$work/release"
  tar -xzf "$work/$tarball" -C "$work/release"
  previous="$(find "$work/release" -type f -name gateon | head -n 1)"
  if [ -z "$previous" ]; then
    echo "check-compat: $tarball holds no gateon binary" >&2
    exit 1
  fi
fi

if [ ! -x "$previous" ]; then
  echo "check-compat: $previous is not an executable file" >&2
  exit 1
fi

cd "$root"
GATEON_COMPAT_PREVIOUS="$previous" GATEON_COMPAT_REQUIRED=1 \
  go test -count=1 -timeout 15m \
  -run 'TestTheLastReleaseUpgradesToThisBuildAndBack|TestARestartIntoThisBuildRefusesNoConnection|TestARestartOfThisBuildLosesNoRequest' \
  ./tests/e2e/
