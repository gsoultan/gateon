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
note "1/6  auth.Service nil-comparisons"
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
note "2/6  session token in web storage"
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
note "3/6  tests building into the repository root"
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
note "4/6  SPDX license header on every source file"
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

# ---------------------------------------------------------------------------
# 5. The management auth chain must never enable DryRun.
#
# AuthBaseConfig.HandleFailure with DryRun set calls next.ServeHTTP on an
# authentication *failure*, without claims on the context. Downstream
# authorization — handlers.RequirePermission and server.authorizeProcedure —
# both read "no claims" as "PasetoAuth never ran, auth is disabled for this
# deployment" and allow the call. So on the management plane DryRun does not
# mean "log the failure and continue unauthenticated"; it means "log the
# failure and continue with full permissions", on all three transports at once.
#
# That overload is deliberate everywhere else: DryRun exists so an operator can
# roll auth out across proxied routes without breaking traffic, and it is set
# only from route middleware config (auth_factory.go, cfg["dry_run"]). Nothing
# reachable by configuration can turn it on for the management API — it would
# take an edit to base_handler.go, which is exactly the kind of one-line change
# that reads as harmless and is not.
#
# The durable fix is to stop overloading nil claims, so an attempted-and-failed
# authentication is distinguishable from no authentication at all. Until then
# this check holds the line. See doc/adr/0006-transport-neutral-authorization.md.
# ---------------------------------------------------------------------------
note "5/6  DryRun on the management auth chain"
dryrun_hits=$( (find internal/server -name '*.go' -not -name '*_test.go' -print0 |
	xargs -0 grep -nE 'DryRun' 2>/dev/null |
	drop_comment_hits) || true)

if [ -n "$dryrun_hits" ]; then
	err "the management auth chain references DryRun"
	printf '%s\n' "$dryrun_hits"
	printf '  DryRun continues past an auth failure with no claims, and both\n'
	printf '  RequirePermission and authorizeProcedure read absent claims as\n'
	printf '  "auth disabled" and allow. On this chain it grants full access.\n'
else
	echo "  ok - the management auth chain does not enable DryRun"
fi

# ---------------------------------------------------------------------------
# 6. Middleware config keys the dashboard writes must be keys Go reads.
#
# A route's middleware config is a map<string,string> passed through verbatim:
# the dashboard writes a key, Go looks one up, and nothing anywhere checks that
# they are the same string. They were not. The editors wrote camelCase
# ("stsSeconds", "allowedOrigins", "clientSecret") while every reader looked up
# snake_case, so 73 settings silently did nothing — and worse than nothing,
# because the editor also *read* the wrong key, so a value already set by a
# server-side template rendered as blank and saving the form left the real value
# in force while the UI showed the new one.
#
# That is the failure mode this check exists for: a rate limit, a CORS origin
# list or an auth secret that the dashboard displays and the gateway does not
# enforce. No compiler sees it, because both sides are string literals in
# different languages.
# ---------------------------------------------------------------------------
note "6/6  Dashboard middleware config keys match the Go readers"
mw_editors="ui/src/components/MiddlewareConfig"
if [ -d "$mw_editors" ]; then
	go_keys=$(grep -rhoE '\["[A-Za-z0-9_]+"\]' internal/middleware/ 2>/dev/null |
		tr -d '["]' | sort -u)
	ui_keys=$(grep -rhoE 'updateConfig\(\s*"[A-Za-z0-9_]+"' "$mw_editors" 2>/dev/null |
		sed -E 's/.*"([A-Za-z0-9_]+)"/\1/' | sort -u)

	# Only camelCase keys are reported: a key with no Go reader at all may
	# legitimately belong to a middleware whose parser this grep cannot see,
	# but a camelCase key whose snake_case form *is* read is unambiguously the
	# bug above.
	orphans=""
	for k in $ui_keys; do
		case "$k" in
		*[A-Z]*)
			snake=$(printf '%s' "$k" | sed -E 's/([a-z0-9])([A-Z])/\1_\2/g' | tr 'A-Z' 'a-z')
			if printf '%s\n' "$go_keys" | grep -qx "$snake"; then
				orphans="$orphans  $k -> Go reads $snake\n"
			fi
			;;
		esac
	done

	if [ -n "$orphans" ]; then
		err "the dashboard writes middleware config keys nothing reads"
		printf "$orphans"
		printf '  The gateway will keep using whatever was there before, while the\n'
		printf '  dashboard shows the new value. Use the snake_case key.\n'
	else
		echo "  ok - every dashboard middleware key has a matching Go reader"
	fi
else
	echo "  ok - no middleware editors present"
fi

printf '\n'
if [ "$fail" -ne 0 ]; then
	printf '\033[31msecurity invariant check failed\033[0m\n'
	exit 1
fi
printf '\033[32mall security invariants hold\033[0m\n'
