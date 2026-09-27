#!/bin/sh
# Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
# SPDX-License-Identifier: MIT
#
# bench-datapath.sh -- benchmark the listener and L4 data path on Linux with
# two CPUs, the deployment target, in a shape benchstat can compare.
#
#   scripts/bench-datapath.sh build <dir>
#       Compile the benchmark binaries of this tree into <dir>.
#
#   scripts/bench-datapath.sh run <count> <bench-regex> <dir>=<out.txt>[:K=V,...] ...
#       Run each <dir>'s binaries <count> times, appending to <out.txt>, with
#       the optional environment. Variants are interleaved -- round 1 of every
#       variant, then round 2 -- so a machine that drifts during the run moves
#       every variant alike instead of the one that happened to run last.
#
# Two engines of one tree:
#   scripts/bench-datapath.sh build /private/tmp/bench/new
#   scripts/bench-datapath.sh run 6 . /private/tmp/bench/new=std.txt \
#       /private/tmp/bench/new=uring.txt:GATEON_PHANTOM=1
#   benchstat std.txt uring.txt
#
# Two commits: build each into its own <dir> and name both in one run.
#
# On Linux the binaries run directly, pinned to CPUs 0-1 when taskset exists.
# Elsewhere they are cross-compiled and run in a podman container limited to
# two CPUs (--cpus 2; rootless podman on macOS has no cpuset controller), with
# what io_uring needs: CAP_IPC_LOCK for ring memory and no seccomp or SELinux
# veto on io_uring_setup. <dir> must be under a path the podman machine
# shares with the host; /private/tmp is.
#
# PKGS overrides the packages benchmarked. LIMIT bounds one binary's run
# (default 20m); -test.timeout does not cover benchmarks, and an engine that
# hangs must fail the run with a goroutine dump, not stall it.
set -eu

PKGS=${PKGS:-"./internal/phantom ./internal/server/entrypoint ./pkg/l4"}
IMAGE=${IMAGE:-docker.io/library/debian:bookworm-slim}
LIMIT=${LIMIT:-20m}

usage() {
	sed -n '5,34p' "$0" >&2
	exit 2
}

build() {
	dir=$1
	mkdir -p "$dir"
	if [ "$(uname -s)" = Linux ]; then
		goos=linux goarch=$(go env GOARCH)
	else
		goos=linux goarch=$(podman info --format '{{.Host.Arch}}')
	fi
	for pkg in $PKGS; do
		name=$(echo "$pkg" | sed 's#^\./##' | tr '/' '_')
		GOOS=$goos GOARCH=$goarch go test -c -o "$dir/$name.test" "$pkg"
	done
	echo "built $(ls "$dir" | wc -l | tr -d ' ') benchmark binaries into $dir for $goos/$goarch"
}

# run_one <binary> <regex> <env list, comma separated> -- prints results
run_one() {
	bin=$1 regex=$2 envs=$3
	args="-test.run ^\$ -test.bench $regex -test.benchmem -test.count 1 -test.timeout 30m"
	if [ "$(uname -s)" = Linux ]; then
		pin=""
		command -v taskset >/dev/null 2>&1 && pin="taskset -c 0,1"
		# shellcheck disable=SC2086 # word splitting of args and env is intended
		env $(echo "$envs" | tr ',' ' ') GOMAXPROCS=2 timeout -s QUIT "$LIMIT" $pin "$bin" $args
		return
	fi
	eflags=""
	for kv in $(echo "$envs" | tr ',' ' '); do
		eflags="$eflags -e $kv"
	done
	# shellcheck disable=SC2086
	podman run --rm --cpus 2 --security-opt seccomp=unconfined \
		--security-opt label=disable --cap-add IPC_LOCK $eflags \
		-v "$(dirname "$bin"):$(dirname "$bin")" "$IMAGE" timeout -s QUIT "$LIMIT" "$bin" $args
}

run() {
	count=$1 regex=$2
	shift 2
	[ $# -gt 0 ] || usage
	i=1
	while [ "$i" -le "$count" ]; do
		for variant in "$@"; do
			dir=${variant%%=*}
			rest=${variant#*=}
			out=${rest%%:*}
			envs=""
			[ "$rest" != "$out" ] && envs=${rest#*:}
			for bin in "$dir"/*.test; do
				echo "round $i/$count: $(basename "$bin") -> $out ${envs:+($envs)}" >&2
				# A failed benchmark must stop the run, not thin out the file:
				# benchstat compares whatever rows it is given.
				log=$(mktemp)
				if ! run_one "$bin" "$regex" "$envs" >"$log" 2>&1; then
					cat "$log" >&2
					rm -f "$log"
					echo "benchmark binary failed: $bin" >&2
					exit 1
				fi
				grep -E '^(Benchmark|goos|goarch|pkg|cpu)' "$log" >>"$out" || true
				rm -f "$log"
			done
		done
		i=$((i + 1))
	done
}

[ $# -ge 1 ] || usage
cmd=$1
shift
case $cmd in
build) [ $# -eq 1 ] || usage; build "$1" ;;
run) [ $# -ge 3 ] || usage; run "$@" ;;
*) usage ;;
esac
