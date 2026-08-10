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

# proto + grpc + buf code generators. Versions come from the `tool` directive in
# go.mod, so they are locked in go.sum and reviewed like any other dependency.
# `@latest` meant the image pulled whatever upstream had tagged at build time:
# the image was not reproducible, and a compromised upstream tag would have been
# compiled straight into the shipped binary — in a process that terminates TLS
# and sees every request.
COPY go.mod go.sum ./
RUN go install tool
ENV PATH="/go/bin:${PATH}"

COPY . .
# Bring in the compiled UI and embed it (sync_assets copies ui/dist ->
# internal/ui/dist, which ui.go embeds via //go:embed all:dist).
COPY --from=ui /ui/dist ./ui/dist
COPY --from=ui /ui/node_modules ./ui/node_modules
# No `go mod tidy` here: it let the image build mutate its own dependency set,
# so the shipped binary could be built against a graph nobody reviewed. The
# committed go.mod/go.sum are authoritative; CI enforces that they are tidy.
RUN PATH="${PATH}:/src/ui/node_modules/.bin" buf generate && \
    go run ./scripts/sync_assets.go && \
    go generate ./internal/ebpf/... && \
    go mod verify

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
# Config lives at /etc/gateon. Without these the process resolves every config
# file relative to its working directory — "/" in a scratch image — so an
# operator who mounts /etc/gateon/global.json gets a gateway that silently
# starts on built-in defaults, and the built-in default has the WAF switched
# off. Naming the paths makes a missing mount a startup error instead.
ENV GATEON_CONFIG_DIR=/etc/gateon \
    GLOBAL_CONFIG_FILE=/etc/gateon/global.json \
    ROUTES_FILE=/etc/gateon/routes.json \
    SERVICES_FILE=/etc/gateon/services.json \
    ENTRYPOINTS_FILE=/etc/gateon/entrypoints.json \
    MIDDLEWARES_FILE=/etc/gateon/middlewares.json \
    TLS_OPTIONS_FILE=/etc/gateon/tls_options.json
WORKDIR /var/lib/gateon
COPY --from=builder /out/gateon /usr/local/bin/gateon
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/gateon"]
