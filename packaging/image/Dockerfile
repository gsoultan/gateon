# syntax=docker/dockerfile:1
# Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
# SPDX-License-Identifier: MIT
#
# The published image (ghcr.io/gsoultan/gateon). It compiles nothing: it copies
# the gateon binary out of the release's own tarballs onto distroless, so the
# binary in the image is byte-for-byte the one in gateon_<version>_linux_<arch>
# .tar.gz -- same commit, same Go toolchain, same PGO profile, same -trimpath,
# same main.Version stamp. packaging/image/build.sh lays the context out:
#
#   linux/amd64/gateon   linux/arm64/gateon   var-lib-gateon/   Dockerfile
#
# and is the only supported way to build it (ADR 0065). The source build that
# `make docker` and CI's docker-smoke use is the repository-root Dockerfile;
# everything from FROM down must match that file's runtime stage except the
# COPY lines, and `build.sh parity` fails the release workflow when it does not.
#
# Nothing here RUNs, so a multi-platform build needs no emulation.

FROM gcr.io/distroless/static-debian12:nonroot
# OCI metadata. The licenses label is the one that matters operationally:
# distroless carries no package manager and no /usr/share/doc, so an image
# scanner or SBOM consumer has nothing else to read a license from.
LABEL org.opencontainers.image.title="Gateon" \
      org.opencontainers.image.description="Ultra-Intelligent Defense Security Gateway" \
      org.opencontainers.image.source="https://github.com/gsoultan/gateon" \
      org.opencontainers.image.url="https://github.com/gsoultan/gateon" \
      org.opencontainers.image.documentation="https://github.com/gsoultan/gateon/blob/main/README.md" \
      org.opencontainers.image.vendor="Gembit Soultan Shirazi" \
      org.opencontainers.image.authors="Gembit Soultan Shirazi <gembit.soultan@gmail.com>" \
      org.opencontainers.image.licenses="MIT"
# The environment is the root Dockerfile's, line for line; its comments say why
# each path is where it is (ADR 0049).
ENV GATEON_PROFILE=standard
ENV GATEON_DATA_DIR=/var/lib/gateon \
    GLOBAL_CONFIG_FILE=/var/lib/gateon/global.json \
    GATEON_GLOBAL_CONFIG_SEED=/etc/gateon/global.json \
    GATEON_CONFIG_DIR=/etc/gateon \
    ROUTES_FILE=/etc/gateon/routes.json \
    SERVICES_FILE=/etc/gateon/services.json \
    ENTRYPOINTS_FILE=/etc/gateon/entrypoints.json \
    MIDDLEWARES_FILE=/etc/gateon/middlewares.json \
    TLS_OPTIONS_FILE=/etc/gateon/tls_options.json
# Owned by nonroot (65532), mode 0700, so a named volume mounted here -- which
# starts as a copy of this directory -- is writable by the gateway and nobody
# else. --chmod, not the source directory's mode, is what makes it 0700: COPY
# of a directory creates the destination 0755 and copies only the contents.
COPY --chown=65532:65532 --chmod=0700 var-lib-gateon /var/lib/gateon
WORKDIR /var/lib/gateon
# TARGETPLATFORM is linux/amd64 or linux/arm64, which is where build.sh put the
# binary extracted from that architecture's tarball.
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/gateon /usr/local/bin/gateon
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/gateon"]
