.PHONY: proto build build-fips test test-race bench clean vuln staticcheck gosec sec ebpf ebpf-docker

## proto: regenerate Go bindings from proto/gateon/v1/*.proto using buf
proto:
	buf generate

## ebpf: compile the XDP/eBPF C program and (re)generate the bpf2go Go bindings.
##       Requires a Linux host with clang/llvm + libbpf headers + kernel headers.
##       The generated gateon_ebpf_bpf*.go and *.o files MUST be committed so a
##       plain `go build` works on any platform without the BPF toolchain.
ebpf:
	go generate ./internal/ebpf/...

## ebpf-docker: same as `ebpf` but runs the codegen inside a Linux container so
##              it is reproducible from macOS/Windows (no local BPF toolchain
##              needed). Generated artifacts land in the working tree to commit.
ebpf-docker:
	docker build -f internal/ebpf/Dockerfile.gen -t gateon-ebpf-gen .
	docker run --rm -v "$(CURDIR)":/src -w /src gateon-ebpf-gen \
		sh -c 'go generate ./internal/ebpf/...'

## build: build the gateon binary
build:
	go build -v -o dist/gateon ./cmd/gateon

## build-fips: build the gateon binary with FIPS 140-2 compliance (BoringCrypto)
build-fips:
	GOEXPERIMENT=boringcrypto go build -v -o dist/gateon-fips ./cmd/gateon

## test: run all tests
test:
	go test -v ./...

## test-race: run all tests with the race detector enabled
test-race:
	go test -race ./...

## bench: run benchmarks with allocation tracking and write CPU/heap profiles
##        (catches perf/alloc regressions; profiles land in dist/ for `go tool pprof`)
bench:
	mkdir -p dist
	go test -run '^$$' -bench . -benchmem -benchtime 100000x \
		-cpuprofile dist/cpu.prof -memprofile dist/mem.prof ./pkg/proxy/ ./internal/telemetry/

## vuln: scan for known vulnerabilities in dependencies and code (govulncheck)
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

## staticcheck: run staticcheck static analysis
staticcheck:
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

## gosec: run the gosec security scanner
gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@latest ./...

## sec: run the full local security gate (vet + vuln + staticcheck + gosec)
sec: vuln staticcheck gosec
	go vet ./...

## clean: clean build artifacts
clean:
	go clean
	rm -rf dist/
