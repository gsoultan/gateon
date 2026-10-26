#!/usr/bin/env bash
# Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
# SPDX-License-Identifier: MIT
#
# Fails when any commit in a range is authored or committed by an AI tool's
# identity, or carries an AI co-author trailer. Cloud agent sessions default to
# committing as "Claude <noreply@anthropic.com>"; GitHub links that address to
# an account and lists it as a contributor. Main was rewritten twice to undo
# that, and the second time was needed because the first left the source alone.
#
# Usage: scripts/check-commit-identity.sh <base> <head>

set -euo pipefail

base=${1:?usage: $0 <base> <head>}
head=${2:?usage: $0 <base> <head>}
pattern='@anthropic\.com|^Claude$'

bad=$(git log --format='%h%x09%an%x09%ae%x09%cn%x09%ce' "$base..$head" |
	awk -F '\t' -v re="$pattern" '$2 ~ re || $3 ~ re || $4 ~ re || $5 ~ re')
trailers=$(git log --format='%h%x09%(trailers:key=Co-authored-by,valueonly,separator=%x2C )' "$base..$head" |
	grep -iE $'\t.*(claude|anthropic)' || true)

if [ -n "$bad$trailers" ]; then
	echo "Commits credited to an AI identity (author, committer or Co-authored-by):"
	[ -n "$bad" ] && printf '%s\n' "$bad"
	[ -n "$trailers" ] && printf '%s\n' "$trailers"
	echo
	echo "Set git config user.name/user.email to a person and rewrite these commits."
	exit 1
fi
echo "commit identity: $(git rev-list --count "$base..$head") commits checked, none credited to an AI identity"
