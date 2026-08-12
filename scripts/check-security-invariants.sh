#!/usr/bin/env bash
# Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
# SPDX-License-Identifier: MIT
#
# Guards the invariants that carry no compile-time protection. The first two
# were violated in shipped code and both failed silently: the gateway served the
# management API unauthenticated, and the dashboard stored an administrator
# token where any script could read it. Neither the compiler, go vet,
# golangci-lint nor tsc objects to any of these.
#
# Run locally with `make check-invariants`; CI runs it on every push.

set -euo pipefail

cd "$(dirname "$0")/.."

fail=0

note() { printf '\n\033[1m%s\033[0m\n' "$1"; }
err() {
	printf '::error::%s\n' "$1"
	fail=1
}

# Drop grep hits whose match sits in a comment, so prose describing a pattern
# does not trip the check on the pattern itself. Filters the annotated output
# rather than the source, to keep reported line numbers pointing at the file.
drop_comment_hits() { grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|\*|/\*)' || true; }

# ---------------------------------------------------------------------------
# 1. An auth.Service must never be compared against nil.
#
# Server.AuthManager and the Auth field on BaseHandlerDeps/ApiService/handlers
# .Deps are all *auth.Holder, which is never nil but is unusable until Setup
# has installed a real Manager. `x == nil` is therefore false at exactly the
# moment authentication is unavailable, and a guard written that way lets the
# request through. auth.Available(x) is the only correct test.
#
# Proto config fields (gc.Auth, conf.Auth) are a different type and are fine, so
# this matches the specific identifiers that hold a service.
#
# One trap worth knowing about: auth.Available answers "can this authenticate
# *right now*", which is a request-time question. Do not use it to decide at
# construction time whether to build an authenticating handler — on a first run
# the answer is no, the handler never gets built, and the gateway then refuses
# forever instead of picking up the service Setup installs. If a constructor
# needs to tolerate a not-yet-available service, make the callee deny on a nil
# verifier (see middleware/auth.PasetoAuth) and build unconditionally.
# ---------------------------------------------------------------------------
note "1/4  auth.Service nil-comparisons"
auth_hits=$( (find internal pkg cmd -name '*.go' -not -name '*_test.go' -print0 |
	xargs -0 grep -nE '(\.AuthManager|deps\.Auth|s\.Auth|svc\.Auth)[[:space:]]*[!=]=[[:space:]]*nil' 2>/dev/null |
	drop_comment_hits) || true)

if [ -n "$auth_hits" ]; then
	err "an auth.Service is compared against nil; use auth.Available(svc) instead"
	printf '%s\n' "$auth_hits"
	printf '  A Holder is never nil. Comparing it to nil reports "auth is present"\n'
	printf '  while it is empty, which is how the first-run bypass worked.\n'
else
	echo "  ok - no auth.Service nil-comparisons"
fi

# ---------------------------------------------------------------------------
# 2. The session token must never reach web storage.
#
# The dashboard renders traffic captured from hostile clients, so a single
# stored-XSS bug plus a readable token equals administrator compromise. The
# token lives only in the HttpOnly gateon_session cookie.
# ---------------------------------------------------------------------------
note "2/4  session token in web storage"
storage_hits=$( (grep -rnE '(localStorage|sessionStorage)\.(setItem|getItem)' ui/src \
	--include='*.ts' --include='*.tsx' 2>/dev/null |
	grep -viE 'token|jwt|paseto|bearer|credential|gateon-auth') || true)
token_hits=$( (grep -rnE '(localStorage|sessionStorage)[^;]*\b(token|jwt|paseto|bearer)\b' ui/src \
	--include='*.ts' --include='*.tsx' 2>/dev/null | drop_comment_hits) || true)

if [ -n "$token_hits" ]; then
	err "a session token is read from or written to web storage"
	printf '%s\n' "$token_hits"
	printf '  Use the HttpOnly gateon_session cookie; see ui/src/store/useAuthStore.ts.\n'
else
	echo "  ok - no token in web storage"
fi
if [ -n "$storage_hits" ]; then
	printf '  (non-credential web storage use, allowed:)\n%s\n' "$storage_hits"
fi

# The auth store must keep excluding the token from what it persists.
if ! grep -q 'partialize' ui/src/store/useAuthStore.ts; then
	err "ui/src/store/useAuthStore.ts no longer calls partialize"
	printf '  Without it, zustand persists the whole state - including the token.\n'
elif grep -A 2 'partialize' ui/src/store/useAuthStore.ts | grep -q 'token'; then
	err "useAuthStore partialize includes the token"
	printf '  Persist the user for shell rendering; never the credential.\n'
else
	echo "  ok - useAuthStore persists user only"
fi

# ---------------------------------------------------------------------------
# 3. Tests must not build into the checkout.
#
# Four e2e tests built gateon_<TestName> and mock_backend_<TestName> into the
# repository root. Besides leaving artifacts behind, a subtest name contains a
# '/', which made the -o path invalid and produced a build that "succeeded"
# and then failed at exec with a confusing error.
# ---------------------------------------------------------------------------
note "3/4  tests building into the repository root"
root_builds=$( (grep -rnE '"go",[[:space:]]*"build",[[:space:]]*"-o",[[:space:]]*[a-zA-Z]' tests/ --include='*.go' 2>/dev/null |
	grep -vE 'filepath\.Join\((env\.Dir|tmpDir|t\.TempDir)') || true)
# Re-check the argument actually resolves under a temp dir.
suspicious=""
while IFS= read -r line; do
	[ -z "$line" ] && continue
	file=${line%%:*}
	var=$(printf '%s' "$line" | sed -nE 's/.*"-o",[[:space:]]*([a-zA-Z_][a-zA-Z0-9_]*).*/\1/p')
	[ -z "$var" ] && continue
	if grep -qE "${var}[[:space:]]*:?=[[:space:]]*filepath\.Join\((env\.Dir|tmpDir)" "$file"; then
		continue
	fi
	suspicious+=$(printf '\n  %s' "$line")
done <<<"$root_builds"

if [ -n "$suspicious" ]; then
	err "a test builds a binary outside t.TempDir()"
	printf '%s\n' "$suspicious"
	printf '  Build into env.Dir (backed by t.TempDir()), which is cleaned up for you.\n'
else
	echo "  ok - all test builds target a temp dir"
fi

# ---------------------------------------------------------------------------
# 4. Every source file declares its license.
#
# LICENSE at the repository root does not travel with a file. The moment one is
# vendored into another module, copied into a container layer, lifted into a
# gist or pasted into an issue, the only license statement that survives is the
# one in the file. Ambiguity there is resolved in the reader's favour, not ours.
#
# golangci-lint's goheader enforces this for Go and gives the better error, but
# CI does not run golangci-lint — only this script — so Go is re-checked here
# rather than relying on a gate that never fires. Nothing at all enforces it for
# .proto or for TypeScript (the dashboard, the e2e suite, the build config), and
# those are exactly the files someone adds without thinking about licensing.
#
# Generated output is exempt: protoc-gen-go, protoc-gen-connect-go and
# protoc-gen-es all copy the leading comment out of the .proto, so fixing the
# .proto fixes the generated file on the next `make proto`.
# ---------------------------------------------------------------------------
note "4/4  SPDX license header on every source file"
SPDX_LINE='SPDX-License-Identifier: MIT'
missing_spdx=""
while IFS= read -r f; do
	[ -f "$f" ] || continue
	case "$f" in
	# protoc-gen-es output; the header comes from the .proto.
	ui/src/services/gen/*) continue ;;
	# Agent/editor tooling checked into the repo, not Gateon source.
	.agents/* | .claude/* | .cursor/* | .gemini/* | .kiro/* | .junie/*) continue ;;
	esac
	if ! head -6 "$f" | grep -qF "$SPDX_LINE"; then
		missing_spdx+=$(printf '\n  %s' "$f")
	fi
done < <(git ls-files '*.go' '*.proto' '*.ts' '*.tsx' 2>/dev/null)

if [ -n "$missing_spdx" ]; then
	err "a source file is missing the SPDX license header"
	printf '%s\n' "$missing_spdx"
	printf '  Add these two lines at the very top of the file:\n'
	printf '    // Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.\n'
	printf '    // %s\n' "$SPDX_LINE"
else
	echo "  ok - every Go, proto and TypeScript source carries the SPDX header"
fi

printf '\n'
if [ "$fail" -ne 0 ]; then
	printf '\033[31msecurity invariant check failed\033[0m\n'
	exit 1
fi
printf '\033[32mall security invariants hold\033[0m\n'
