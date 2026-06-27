# syntax=docker/dockerfile:1
#
# Multi-stage production build for gateon. It reproduces the CI pipeline so the
# image is self-contained (the embedded UI, generated proto bindings, and eBPF
# loader bindings are produced here rather than relying on committed artifacts):
#   1. ui      — build the React/Vite dashboard with Bun.
#   2. builder — generate proto + eBPF bindings, embed the UI, build a static,
#                CGO-free, PGO-optimized binary.
#   3. runtime — distroless static, non-root.
#
# Build from the repo root:  make docker   (or: docker build -t gateon:latest .)

# ---- Stage 1: UI ------------------------------------------------------------
FROM oven/bun:1 AS ui
WORKDIR /ui
# Install deps first for layer caching, then build.
COPY ui/package.json ui/bun.lock* ./
RUN bun install
COPY ui/ ./
RUN bun run build

# ---- Stage 2: builder -------------------------------------------------------
# bookworm + clang/llvm/libbpf lets `go generate` compile the XDP program so the
# Linux build (manager_linux.go) links the bpf2go loader. Pin to go.mod's Go.
FROM golang:1.26-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm libbpf-dev libelf-dev linux-libc-dev gcc-multilib make \
    && rm -rf /var/lib/apt/lists/*
ENV BPF2GO_CC=clang BPF2GO_STRIP=llvm-strip

WORKDIR /src
# Module cache layer.
COPY go.mod go.sum ./
RUN go mod download

# proto + grpc + buf code generators.
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest && \
    go install github.com/bufbuild/buf/cmd/buf@latest
ENV PATH="/go/bin:${PATH}"

COPY . .
# Bring in the compiled UI and embed it (sync_assets copies ui/dist ->
# internal/ui/dist, which ui.go embeds via //go:embed all:dist).
COPY --from=ui /ui/dist ./ui/dist
RUN buf generate && \
    go run ./scripts/sync_assets.go && \
    go generate ./internal/ebpf/... && \
    go mod tidy

# Static, CGO-free binary. The Go toolchain auto-applies cmd/gateon/default.pgo
# when present (see `make pgo-profile`). -trimpath + -s -w shrink the binary.
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /out/gateon ./cmd/gateon

# ---- Stage 3: runtime -------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot
# Go 1.25+ derives GOMAXPROCS from the cgroup CPU quota automatically, so the
# gateway does not over-subscribe host cores under a CPU limit. Default to the
# balanced resource profile; override GATEON_PROFILE / GOMEMLIMIT at deploy time.
ENV GATEON_PROFILE=standard
COPY --from=builder /out/gateon /usr/local/bin/gateon
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/gateon"]
