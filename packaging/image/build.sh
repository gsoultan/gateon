#!/usr/bin/env bash
# Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
# SPDX-License-Identifier: MIT
#
# Builds, publishes and checks the gateon container image from a release's own
# tarballs (ADR 0065). The release workflow runs it three ways -- a tag push, a
# manual publish of an existing tag, and the dry run -- and they differ only in
# where the tarballs come from and which registry receives the image, so a dry
# run that passes has exercised every command a tag will run.
#
#   build.sh resolve   TAG=v1.2.3 [REPO=owner/name]  -> key=value lines
#   build.sh stage     ARCHIVES=dir CONTEXT=dir [VERSION=] [REVISION=]
#   build.sh build     CONTEXT IMAGE TAGS VERSION REVISION CREATED  -> digest=
#   build.sh verify    CONTEXT IMAGE DIGEST VERSION [ENGINE=docker|podman]
#   build.sh parity
#   build.sh selftest
#
# resolve refuses anything that is not an existing, published release tag.
# stage refuses a tarball checksums.txt does not vouch for, and a binary that is
# not CGO-free, -trimpath and PGO-built with the expected version stamp. verify
# pulls what was pushed, by digest, one platform at a time, and refuses an image
# whose binary differs by one byte from the tarball's, that runs as anyone but
# uid 65532, or that does not serve /healthz and drain on SIGTERM.

# Inputs arrive as environment variables (TAGS, DIGEST, ...), checked by need().
# shellcheck disable=SC2153
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PLATFORMS=(linux/amd64 linux/arm64)
ENGINE="${ENGINE:-docker}"
REPO="${REPO:-${GITHUB_REPOSITORY:-gsoultan/gateon}}"
# Semver only. The workflow triggers on "v*", but this also vets a dispatch
# input, and a bare prefix match would let "v1;anything" through.
TAG_RE='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'
TAB=$'\t'

CLEANUP_CONTAINERS=()
CLEANUP_DIRS=()
cleanup() {
	local c d
	for c in "${CLEANUP_CONTAINERS[@]+"${CLEANUP_CONTAINERS[@]}"}"; do
		$ENGINE rm -f "$c" >/dev/null 2>&1 || true
	done
	for d in "${CLEANUP_DIRS[@]+"${CLEANUP_DIRS[@]}"}"; do rm -rf "$d"; done
}
trap cleanup EXIT

die() {
	printf '::error::%s\n' "$*" >&2
	exit 1
}
need() { [ -n "${!1:-}" ] || die "$1 is required"; }

sha256() {
	if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

# ---------------------------------------------------------------------------
# resolve: TAG -> version, revision, created, and the image tags to apply.
#
# `latest` follows GitHub's "Latest release" marker rather than a sort of the
# tags: version numbering restarted at v1.0.0 after v2.7.0, and publishing an
# older tag's image must never move `latest` backwards. MAJOR.MINOR moves only
# when the tag is the highest patch release in its line, for the same reason.
# A prerelease gets its exact version and nothing else.
cmd_resolve() {
	need TAG
	[[ "$TAG" =~ $TAG_RE ]] || die "'$TAG' is not a release tag (want vMAJOR.MINOR.PATCH[-PRERELEASE])"
	git -C "$ROOT" rev-parse -q --verify "refs/tags/$TAG" >/dev/null ||
		die "tag $TAG does not exist in this repository"
	local draft
	draft="$(gh release view "$TAG" -R "$REPO" --json isDraft --jq .isDraft 2>/dev/null)" ||
		die "tag $TAG has no GitHub release: only a published release's tarballs become an image"
	[ "$draft" = "false" ] || die "the $TAG release is a draft"

	local version="${TAG#v}" major minor highest latest
	IFS=. read -r major minor _ <<<"${version%%-*}"
	highest="$(git -C "$ROOT" tag -l "v${major}.${minor}.*" |
		grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -t. -k3,3n | tail -1 || true)"
	latest="$(gh api "repos/$REPO/releases/latest" --jq .tag_name 2>/dev/null || true)"

	echo "tag=$TAG"
	echo "version=$version"
	echo "revision=$(git -C "$ROOT" rev-list -n 1 "$TAG")"
	echo "created=$(git -C "$ROOT" log -1 --format=%ct "$TAG")"
	echo "tags=$(image_tags "$TAG" "$highest" "$latest")"
}

# image_tags TAG HIGHEST_IN_LINE LATEST_RELEASE -> the tags to push.
image_tags() {
	local tag="$1" version="${1#v}" major minor tags
	IFS=. read -r major minor _ <<<"${version%%-*}"
	tags="$version"
	if [[ "$version" != *-* ]]; then
		if [ "$2" = "$tag" ]; then tags="$tags ${major}.${minor}"; fi
		if [ "$3" = "$tag" ]; then tags="$tags latest"; fi
	fi
	echo "$tags"
}

# selftest: the decisions above that need no registry, network or tag.
cmd_selftest() {
	local fails=0 got
	expect() {
		if [ "$2" != "$3" ]; then
			printf '::error::%s: got "%s", want "%s"\n' "$1" "$2" "$3" >&2
			fails=$((fails + 1))
		fi
	}
	expect "newest release" "$(image_tags v1.1.0 v1.1.0 v1.1.0)" "1.1.0 1.1 latest"
	expect "older line's newest patch" "$(image_tags v1.0.3 v1.0.3 v1.1.0)" "1.0.3 1.0"
	expect "superseded patch" "$(image_tags v1.0.2 v1.0.3 v1.1.0)" "1.0.2"
	expect "prerelease, even if marked latest" "$(image_tags v1.2.0-rc.1 v1.1.0 v1.2.0-rc.1)" "1.2.0-rc.1"
	expect "no latest release known" "$(image_tags v1.1.0 v1.1.0 "")" "1.1.0 1.1"
	local t
	for t in v1.1.0 v0.0.1 v10.20.30 v1.2.0-rc.1 v1.2.0-beta.2-x; do
		[[ "$t" =~ $TAG_RE ]] || expect "accept $t" refused accepted
	done
	# shellcheck disable=SC2016 # the $(id) is the input under test, unexpanded
	for t in main 1.1.0 v1.1 v01.1.0 'v1.1.0;id' 'v1.1.0 ' 'v1.1.0$(id)' v1.1.0-; do
		if [[ "$t" =~ $TAG_RE ]]; then expect "refuse '$t'" accepted refused; fi
	done
	got="$(printf 'FROM gcr.io/distroless/x\n# c\nENV A=1 \\\n    B=2\nCOPY a b\nUSER u\n' >"${TMPDIR:-/tmp}/rs.$$" && runtime_stage "${TMPDIR:-/tmp}/rs.$$")"
	rm -f "${TMPDIR:-/tmp}/rs.$$"
	expect "runtime_stage folds and filters" "$got" "$(printf 'FROM gcr.io/distroless/x\nENV A=1 B=2\nUSER u')"
	[ "$fails" -eq 0 ] || die "$fails selftest case(s) failed"
	echo "selftest ok"
}

# ---------------------------------------------------------------------------
# stage: release tarballs -> a build context.
archive_for() {
	local arch="$1" found=()
	shopt -s nullglob
	found=("$ARCHIVES"/gateon_*_linux_"$arch".tar.gz)
	shopt -u nullglob
	[ "${#found[@]}" -eq 1 ] ||
		die "want exactly one gateon_*_linux_${arch}.tar.gz in $ARCHIVES, found ${#found[@]}"
	echo "${found[0]}"
}

# A tarball counts only if checksums.txt names it: `sha256sum -c
# --ignore-missing` alone passes when the line is absent.
check_sum() {
	local tarball="$1" name line
	name="$(basename "$tarball")"
	line="$(grep -E "^[0-9a-f]{64}  ${name//./\\.}\$" "$ARCHIVES/checksums.txt")" ||
		die "checksums.txt does not list $name"
	(cd "$ARCHIVES" && printf '%s\n' "$line" | sha256 -c - >/dev/null) ||
		die "$name does not match checksums.txt"
}

# The properties the image promises, read from the binary rather than assumed
# from the build configuration. (`go version -m` omits -ldflags whenever
# -trimpath is set, so the version stamp is checked in the binary itself.)
check_binary() {
	local bin="$1" arch="$2" info want
	info="$(go version -m "$bin")" || die "$bin is not a Go binary"
	for want in "build${TAB}CGO_ENABLED=0" "build${TAB}GOOS=linux" \
		"build${TAB}GOARCH=$arch" "build${TAB}-trimpath=true"; do
		grep -qF "$want" <<<"$info" || die "$bin: build info lacks '$want'"
	done
	grep -qE "^${TAB}build${TAB}-pgo=" <<<"$info" || die "$bin was built without PGO"
	if [ -n "${REVISION:-}" ]; then
		grep -qF "build${TAB}vcs.revision=$REVISION" <<<"$info" || die "$bin was not built from $REVISION"
		grep -qF "build${TAB}vcs.modified=false" <<<"$info" || die "$bin was built from a modified tree"
	fi
	# Not grep -q: it exits at the first match, strings dies of SIGPIPE, and
	# pipefail turns the match into a failure.
	strings -n 3 "$bin" | grep -xF "$VERSION" >/dev/null || die "$bin does not carry the version stamp $VERSION"
}

cmd_stage() {
	need ARCHIVES
	need CONTEXT
	local derived
	derived="$(basename "$(archive_for amd64)")"
	derived="${derived#gateon_}"
	derived="${derived%_linux_amd64.tar.gz}"
	if [ -n "${VERSION:-}" ] && [ "$VERSION" != "$derived" ]; then
		die "the tarballs are version $derived, expected $VERSION"
	fi
	VERSION="$derived"

	rm -rf "$CONTEXT"
	mkdir -p "$CONTEXT"
	local plat arch tarball
	for plat in "${PLATFORMS[@]}"; do
		arch="${plat#linux/}"
		tarball="$(archive_for "$arch")"
		check_sum "$tarball"
		mkdir -p "$CONTEXT/$plat"
		tar -xzf "$tarball" -C "$CONTEXT/$plat" --strip-components=1 "gateon_${VERSION}_linux_${arch}/gateon"
		check_binary "$CONTEXT/$plat/gateon" "$arch"
		echo "staged $plat: $(sha256 "$CONTEXT/$plat/gateon" | cut -d' ' -f1) from $(basename "$tarball")" >&2
	done
	mkdir -m 0700 "$CONTEXT/var-lib-gateon"
	cp "$ROOT/packaging/image/Dockerfile" "$CONTEXT/Dockerfile"
	echo "version=$VERSION"
}

# ---------------------------------------------------------------------------
# build: one multi-platform build, pushed with an SBOM and a max-mode
# provenance attestation. SOURCE_DATE_EPOCH (the release commit's time) stamps
# the image config with the commit's time rather than the job's.
cmd_build() {
	local v
	for v in CONTEXT IMAGE TAGS VERSION REVISION CREATED; do need "$v"; done
	local platforms t key val created_iso
	platforms="$(IFS=,; echo "${PLATFORMS[*]}")"
	local args=(buildx build --platform "$platforms")
	for t in $TAGS; do args+=(--tag "$IMAGE:$t"); done
	created_iso="$(date -u -d "@$CREATED" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null ||
		date -u -r "$CREATED" +%Y-%m-%dT%H:%M:%SZ)"
	# Labels for `docker inspect`; the same as annotations on the index and each
	# manifest, which is what a registry UI (GHCR links the package to the
	# repository from .source) and `docker buildx imagetools inspect` read.
	while IFS='=' read -r key val; do
		args+=(--label "$key=$val" --annotation "index,manifest:$key=$val")
	done <<EOF
org.opencontainers.image.version=$VERSION
org.opencontainers.image.revision=$REVISION
org.opencontainers.image.created=$created_iso
org.opencontainers.image.source=https://github.com/gsoultan/gateon
org.opencontainers.image.licenses=MIT
org.opencontainers.image.title=Gateon
org.opencontainers.image.description=Ultra-Intelligent Defense Security Gateway
EOF
	args+=(--build-arg "SOURCE_DATE_EPOCH=$CREATED"
		--provenance=mode=max --sbom=true
		--metadata-file "$CONTEXT.metadata.json" --push "$CONTEXT")
	docker "${args[@]}" >&2
	local digest
	digest="$(jq -r '."containerimage.digest"' "$CONTEXT.metadata.json")"
	[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "buildx reported no image digest"
	echo "digest=$digest"
}

# ---------------------------------------------------------------------------
# verify: what the registry now serves is what was staged, and it runs.
wait_healthy() {
	local name="$1" port="$2" i code
	for i in $(seq 1 90); do
		if [ "$($ENGINE inspect --format '{{.State.Running}}' "$name")" != "true" ]; then
			$ENGINE logs "$name" >&2 || true
			die "$name exited during startup"
		fi
		code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/healthz" || true)"
		if [ "$code" = "200" ]; then
			echo "  /healthz 200 after ${i}s"
			return 0
		fi
		sleep 1
	done
	$ENGINE logs "$name" >&2 || true
	die "$name never served /healthz"
}

# The uid of the gateway process as the kernel sees it, which is what matters;
# the image config's USER is only what was asked for.
# docker top runs the host's ps and keeps the rows whose PID is the container's,
# so it needs a pid column; podman top takes its own descriptors.
process_uid() {
	if [ "$ENGINE" = "podman" ]; then
		$ENGINE top "$1" uid | awk 'NR == 2 { print $NF }'
	else
		$ENGINE top "$1" -o pid,uid | awk 'NR == 2 { print $NF }'
	fi
}

verify_platform() {
	local plat="$1" ref="$IMAGE@$DIGEST" name tmp got port
	name="gateon-verify-${plat#linux/}-$$"
	echo "verify $plat ($ref)"
	# PULL_OPTS is for checking a local plain-HTTP registry with podman
	# (--tls-verify=false); docker already trusts localhost.
	# shellcheck disable=SC2086
	$ENGINE pull -q ${PULL_OPTS:-} --platform "$plat" "$ref" >/dev/null
	$ENGINE create --platform "$plat" --name "$name" -p 127.0.0.1::8080 "$ref" >/dev/null
	CLEANUP_CONTAINERS+=("$name")
	tmp="$(mktemp -d)"
	CLEANUP_DIRS+=("$tmp")

	got="$($ENGINE inspect --format '{{.Config.User}}' "$name")"
	[ "$got" = "nonroot:nonroot" ] || die "$plat: image user is '$got', want nonroot:nonroot"
	got="$($ENGINE inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$name")"
	[ "$got" = "$VERSION" ] || die "$plat: version label is '$got', want '$VERSION'"

	# Byte-identical to the staged binary, which stage checked against the
	# release checksums -- this is also what proves the architecture.
	$ENGINE cp "$name:/usr/local/bin/gateon" "$tmp/gateon"
	cmp -s "$tmp/gateon" "$CONTEXT/$plat/gateon" || die "$plat: the image's binary differs from the tarball's"
	echo "  binary identical to the tarball's"
	$ENGINE export -o "$tmp/fs.tar" "$name"
	got="$(tar -tvf "$tmp/fs.tar" | grep -E ' (\./)?var/lib/gateon/?$' || true)"
	[[ "$got" == drwx------* && "$got" == *65532* ]] ||
		die "$plat: /var/lib/gateon is not mode 0700 owned by 65532: '$got'"
	echo "  /var/lib/gateon 0700 uid 65532"

	# RUN_PLATFORMS narrows which platforms are started, for a host that can
	# emulate neither (an Apple-silicon podman machine runs no amd64). The
	# workflow leaves it unset and starts both, arm64 under QEMU.
	if [[ " ${RUN_PLATFORMS:-${PLATFORMS[*]}} " != *" $plat "* ]]; then
		echo "  not started: $plat is not in RUN_PLATFORMS"
		return 0
	fi
	$ENGINE start "$name" >/dev/null
	port="$($ENGINE port "$name" 8080/tcp | head -1 | sed 's/.*://')"
	wait_healthy "$name" "$port"
	got="$(process_uid "$name")"
	[ "$got" = "65532" ] || die "$plat: the gateway runs as uid '$got', want 65532"
	echo "  gateway process uid 65532"
	$ENGINE stop -t 30 "$name" >/dev/null
	got="$($ENGINE inspect --format '{{.State.ExitCode}}' "$name")"
	case "$got" in
	0 | 143) echo "  drained on SIGTERM, exit $got" ;;
	*) die "$plat: exit code $got on SIGTERM" ;;
	esac
}

cmd_verify() {
	local v plat
	for v in CONTEXT IMAGE DIGEST VERSION; do need "$v"; done
	for plat in "${PLATFORMS[@]}"; do verify_platform "$plat"; done
}

# ---------------------------------------------------------------------------
# parity: the published image and the source-built one share a runtime stage.
# Every instruction from the distroless FROM down, comments dropped and
# continuation lines folded, must match -- except COPY and ARG, the only lines
# that have to differ: one copies from a builder stage, the other from tarballs.
runtime_stage() {
	awk '
		/^FROM gcr\.io\/distroless\// { on = 1 }
		!on || /^[[:space:]]*(#|$)/ { next }
		{
			line = $0
			sub(/^[[:space:]]+/, "", line)
			cont = sub(/[[:space:]]*\\$/, "", line)
			buf = (buf == "" ? line : buf " " line)
			if (!cont) { print buf; buf = "" }
		}' "$1" | grep -vE '^(COPY|ARG) '
}

cmd_parity() {
	local a b
	a="$(runtime_stage "$ROOT/Dockerfile")"
	b="$(runtime_stage "$ROOT/packaging/image/Dockerfile")"
	[ -n "$a" ] || die "no distroless runtime stage in Dockerfile"
	if [ "$a" != "$b" ]; then
		diff <(echo "$a") <(echo "$b") >&2 || true
		die "packaging/image/Dockerfile's runtime stage differs from Dockerfile's"
	fi
	echo "runtime stages match ($(wc -l <<<"$a" | tr -d ' ') instructions)"
}

case "${1:-}" in
resolve) cmd_resolve ;;
stage) cmd_stage ;;
build) cmd_build ;;
verify) cmd_verify ;;
parity) cmd_parity ;;
selftest) cmd_selftest ;;
*) die "usage: $0 resolve|stage|build|verify|parity|selftest" ;;
esac
