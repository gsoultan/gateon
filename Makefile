VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
HAS_EBPF := $(wildcard internal/ebpf/gateon_ebpf_bpf*.go)
ifeq ($(HAS_EBPF),)
	BUILD_TAGS ?= noebpf
else
	BUILD_TAGS ?=
endif
# Container runtime for ebpf-docker. podman is a drop-in replacement and is the
# likely one to have on a Mac without Docker Desktop: `make ebpf-docker CONTAINER=podman`.
CONTAINER ?= docker
LDFLAGS = -s -w -X main.Version=$(VERSION)
GOBUILD = go build -v -ldflags="$(LDFLAGS)" -trimpath -tags=$(BUILD_TAGS)

.PHONY: proto models build build-fips release deb test test-race bench clean vuln staticcheck gosec sec check-invariants check-config check-coverage check-folders ebpf ebpf-docker pgo-profile docker

## proto: regenerate Go bindings from proto/gateon/v1/*.proto using buf
proto:
	./scripts/buf-generate.sh

## models: compile the default WASM-based AI traffic prediction model.
models:
	GOOS=wasip1 GOARCH=wasm go build -o internal/ai/models/default/model.wasm internal/ai/models/default/main.go

## ebpf: compile the XDP/eBPF C program and (re)generate the bpf2go Go bindings.
##       Requires a Linux host with clang/llvm + libbpf headers + kernel headers.
##       The generated gateon_ebpf_bpf*.go and *.o are build artifacts and are
##       NOT committed — ci.yml, security.yml, release.yml and the Dockerfile all
##       install clang and run this step, the same way proto/ and ui/services/gen
##       are regenerated rather than tracked. On macOS use `make ebpf-docker`.
ebpf:
	go generate ./internal/ebpf/...

## ebpf-docker: same as `ebpf` but runs the codegen inside a Linux container so
##              it is reproducible from macOS/Windows (no local BPF toolchain
##              needed). Generated artifacts land in the working tree, ignored.
ebpf-docker:
	$(CONTAINER) build -f internal/ebpf/Dockerfile.gen -t gateon-ebpf-gen .
	$(CONTAINER) run --rm -v "$(CURDIR)":/src:Z -w /src gateon-ebpf-gen \
		sh -c 'go generate ./internal/ebpf/...'

## build: build the gateon binary for the current host. The Go toolchain automatically
##        applies Profile-Guided Optimization when cmd/gateon/default.pgo exists.
## ui-assets: build the dashboard and sync it into the embed directory.
##            Without this the binary embeds whatever internal/ui/dist held at
##            checkout, so a local build silently ships a stale dashboard.
ui-assets:
	cd ui && bun run build
	go run ./scripts/sync_assets.go

build: models ui-assets
	mkdir -p dist
	$(GOBUILD) -o dist/gateon ./cmd/gateon

## release: build optimized linux binaries for production (amd64 and arm64).
release: models
	mkdir -p dist
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o dist/gateon-amd64 ./cmd/gateon
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o dist/gateon-arm64 ./cmd/gateon

## deb: build the .deb packages for amd64 and arm64 using nfpm.
deb: release
	@# nFPM standalone doesn't always expand env vars in 'src' fields, so we use sed to pre-process the config.
	sed 's/$${ARCH}/amd64/g' nfpm.yaml > dist/nfpm-amd64.yaml
	sed 's/$${ARCH}/arm64/g' nfpm.yaml > dist/nfpm-arm64.yaml
	VERSION=$(VERSION) ARCH=amd64 go run github.com/goreleaser/nfpm/v2/cmd/nfpm@latest pkg --config dist/nfpm-amd64.yaml --target dist/gateon_amd64.deb
	VERSION=$(VERSION) ARCH=arm64 go run github.com/goreleaser/nfpm/v2/cmd/nfpm@latest pkg --config dist/nfpm-arm64.yaml --target dist/gateon_arm64.deb

## pgo-profile: capture a CPU profile from representative benchmarks and install
##              it as cmd/gateon/default.pgo, which `make build`/`go build` then
##              apply automatically (PGO). The benchmarks exercise the full
##              request path (proxy + middleware chain). For best results in
##              production, replace it with a profile captured live from the
##              pprof endpoint: set GATEON_PPROF_ADDR and fetch
##              /debug/pprof/profile?seconds=60 under real load.
##              -o is not optional: `go test` KEEPS the compiled test binary in
##              the current directory whenever a profiling flag is passed, so
##              without it this target drops ~150MB of untracked middleware.test
##              and proxy.test into the repository root, where neither is
##              gitignored and both are one `git add -A` away from a commit.
pgo-profile:
	mkdir -p dist
	go test -run '^$$' -bench 'ServeHTTP|GetOrCreateProxy' -benchtime 3s \
		-o dist/pgo-proxy.test -cpuprofile dist/pgo-proxy.prof ./pkg/proxy/
	go test -run '^$$' -bench 'InfraChain' -benchtime 3s \
		-o dist/pgo-mw.test -cpuprofile dist/pgo-mw.prof ./internal/middleware/
	go tool pprof -proto dist/pgo-proxy.prof dist/pgo-mw.prof > cmd/gateon/default.pgo
	@echo "Wrote cmd/gateon/default.pgo — 'make build' now applies PGO."

## docker: build the production container image (multi-stage, CGO-free static).
docker:
	docker build -t gateon:latest .

## build-fips: build the gateon binary with FIPS 140-2 compliance (BoringCrypto)
build-fips:
	GOEXPERIMENT=boringcrypto go build -v -o dist/gateon-fips ./cmd/gateon

## test: run all tests
test:
	go test -v ./...

## test-race: run all tests with the race detector enabled
test-race:
	go test -race ./...

## bench: run benchmarks with allocation tracking, sampled for benchstat.
##        Writes dist/bench.txt; compare two runs with
##          go run golang.org/x/perf/cmd/benchstat@latest old.txt new.txt
##        Only ever compare runs from the same machine, otherwise the delta is
##        measuring the hardware.
##
##        internal/middleware is included because it is the full infrastructure
##        chain every proxied request passes through — the proof AGENTS.md asks
##        for on hot-path changes — and it was missing here.
##
##        -benchtime 1s -count 8, not the previous 100x: 100 iterations is far
##        too few to settle, and it reported BenchmarkBufferPoolGetPut at 62ns
##        against 4.6ns when actually given time to run. A benchmark that
##        reports a number an order of magnitude out is worse than none, because
##        it gets quoted.
bench:
	mkdir -p dist
	go test -run '^$$' -bench . -benchmem -benchtime 1s -count 8 \
		./internal/middleware/ ./pkg/proxy/ ./internal/telemetry/ | tee dist/bench.txt

## vuln: scan for known vulnerabilities in dependencies and code (govulncheck)
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

## staticcheck: run staticcheck static analysis
staticcheck:
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

## gosec: run the gosec security scanner.
##        G115 (integer conversion overflow) is excluded: it fires 81 times on
##        int->int32/uint conversions that are bounded by construction, and a
##        gate nobody can read is a gate nobody runs. Exclude-dirs cover
##        generated protobuf, the e2e harness, and Go files vendored inside the
##        bun cache under ui/.
gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@latest \
		-exclude=G115 \
		-exclude-dir=proto -exclude-dir=tests -exclude-dir=ui \
		-exclude-generated \
		./...

## check-invariants: assert the auth/storage/test-hygiene invariants that have
##                    no compile-time protection (see scripts/ for why each exists)
check-invariants:
	./scripts/check-security-invariants.sh

## check-config: assert every *Config proto field is read by some Go code.
##               Catches controls that render in the dashboard and do nothing --
##               twice now those were security controls reporting success while
##               enforcing nothing. Known debt lives in
##               scripts/checkconfig/baseline.txt; only new offenders fail.
check-config:
	go run ./scripts/checkconfig

## check-folders: assert arch's ten-file package limit as a ratchet. The nine
##                packages already over it are pinned at their current size in
##                scripts/checkfolders/baseline.txt: they may shrink, they may
##                not grow, and a tenth may not appear. Splitting all nine is a
##                months-long refactor of the request path; leaving the rule
##                unenforced is how they got this big.
check-folders:
	go run ./scripts/checkfolders

## check-coverage: assert no package loses its tests or drops below its recorded
##                 floor. A ratchet, not a target -- see scripts/checkcoverage.
##
##                 cmd/gateon is excluded: `go test -cover` over the whole tree
##                 fails to link it against the proto package on Go 1.27 with
##                 "fingerprint mismatch", while the same package builds, tests
##                 and covers cleanly on its own. That is a toolchain problem,
##                 not a coverage one, and gating on it would make this target
##                 red for a reason it cannot describe.
##
##                 The baseline is authoritative for LINUX, because CI is what
##                 enforces it. Packages with build-tagged platform files cover
##                 differently elsewhere: on macOS internal/ebpf and
##                 internal/phantom compile only their stubs, so a smaller
##                 denominator reads as higher coverage. Running this on a Mac
##                 will print "rose" notes for those two; that is the platform
##                 talking, not progress.
check-coverage:
	@go test -cover $$(go list ./... | grep -v 'cmd/gateon') | tee /dev/stderr | go run ./scripts/checkcoverage

## sec: run the full local security gate (vet + vuln + staticcheck + gosec + invariants)
sec: vuln staticcheck gosec check-invariants check-config check-folders
	go vet ./...

## lint: run golangci-lint over the whole tree (reports pre-existing debt too)
lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run ./...

## lint-new: lint only code changed since LINT_BASE (default: origin/main).
##           This is the gate for new work — it ignores pre-existing findings.
LINT_BASE ?= origin/main
lint-new:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run \
		--new-from-rev=$(LINT_BASE) --whole-files=false ./...

## lint-fix: apply the formatters (gofmt + goimports) via golangci-lint
lint-fix:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest fmt ./...

## clean: clean build artifacts
clean:
	go clean
	rm -rf dist/
