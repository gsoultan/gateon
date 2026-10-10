# 65. The published image is the release tarball's binary

Date: 2026-10-05

## Status

Accepted. `ops` (the shipped artifact and the release workflow) drives; `sec`
co-signs the registry credential, the dispatch input and the publish guard.

## Context

The Helm chart's default image has been `ghcr.io/gsoultan/gateon:<appVersion>`
since before any image existed there. Nothing published one: `.goreleaser.yaml`
had no `dockers`, no workflow pushed to a registry, and the chart README told
every user to build their own. v1.0.0 and v1.1.0 shipped tarballs, deb, rpm,
SBOMs and checksums for linux amd64 and arm64, and no image.

Three requirements shaped the fix:

1. The image's binary should be the release's binary -- same commit, toolchain,
   PGO profile, `-trimpath`, `CGO_ENABLED=0` and version stamp -- so that what
   was tested and checksummed as the release is what runs in a cluster.
2. A path that runs only on a tag is untested by construction; release.yml
   drifted onto an offline runner for two weeks that way. The dry run has to
   exercise the image path, not a lookalike of it.
3. v1.1.0 already exists and must get its image without re-tagging.

## Decision

1. **The image is built from the release's tarballs, not from source.**
   `packaging/image/build.sh stage` checks each linux tarball against the
   release's `checksums.txt` (a tarball the file does not list is refused, which
   `sha256sum -c --ignore-missing` alone would pass), extracts the binary, and
   reads its build info: `CGO_ENABLED=0`, `GOOS=linux`, the right `GOARCH`,
   `-trimpath=true`, a `-pgo=` setting, `vcs.revision` equal to the tag's commit,
   `vcs.modified=false`, and the version string in the binary.
   `packaging/image/Dockerfile` then COPYs it onto
   `gcr.io/distroless/static-debian12:nonroot`. Nothing RUNs, so building
   arm64 on an amd64 runner needs no emulation.

2. **One script for three triggers.** A tag push takes the tarballs from the
   release goreleaser has just published; a dispatch with `publish_tag` takes
   them from that existing release; the dry run takes the snapshot tarballs
   from the goreleaser job's artifact. All three run the same `stage`, `build`
   (one `docker buildx build --platform linux/amd64,linux/arm64 --push`) and
   `verify`. The dry run pushes to a `registry:2` service container inside the
   job, so the only differences from a tag are where the tarballs come from and
   the registry's name.

3. **goreleaser's `dockers_v2` is not used.** It would satisfy (1) for a tag,
   but an existing tag could get its image through goreleaser only by
   rebuilding, on whatever Go `setup-go` resolves that day -- not the binary
   the release shipped. Its snapshot mode also builds one `--load`ed image per
   platform rather than the multi-platform index with attestations that a tag
   pushes, so its dry run tests a different build than the real one.

4. **Verify what the registry serves.** After the push, `verify` pulls each
   platform by digest and requires: the binary byte-identical to the staged
   one (which also proves the architecture), image user `nonroot:nonroot`, the
   version label, `/var/lib/gateon` mode 0700 owned by 65532, `/healthz` 200,
   the process's uid 65532 as the kernel reports it, and exit 0 or 143 within
   30 s of SIGTERM. arm64 runs under QEMU. The provenance attestation is made
   after verify, so a digest that failed it is never attested.

5. **Tags.** `X.Y.Z` always. `X.Y` only when the tag is the highest patch
   release of its line. `latest` only when the tag is GitHub's Latest release
   -- not a semver sort, because numbering restarted at v1.0.0 after v2.7.0.
   Prereleases (`-suffix`) get their exact version only. So publishing an
   older tag never moves `X.Y` or `latest` backwards.

6. **Credentials and trust.** The push uses the job's `GITHUB_TOKEN` with
   `packages: write` (no personal token), passed to `docker login` on stdin.
   Workflow permissions default to `contents: read`; only the goreleaser job
   writes releases and only the `image` job can push packages, so the dry run,
   which any branch can dispatch, holds neither. `publish_tag` reaches the
   script through the environment, never interpolated into shell; it must be
   `vMAJOR.MINOR.PATCH[-PRERELEASE]`, an existing tag, with a published
   (non-draft) GitHub release, and the dispatch must run from main. A tag whose
   tree has `packaging/image/Dockerfile` is built with that file; older tags
   (v1.1.0) use main's.

7. **Attestations.** BuildKit attaches an SPDX SBOM and a `mode=max` SLSA
   provenance to the index; `actions/attest-build-provenance` adds a Sigstore
   attestation verifiable with `gh attestation verify`. `SOURCE_DATE_EPOCH` is
   the tag commit's time, so the image config is stamped with the commit, not
   the job.

8. **One runtime stage, checked.** The source-built image (`Dockerfile`, used
   by `make docker` and docker-smoke) and the published one must have the same
   runtime stage: every instruction from the distroless `FROM` down except
   `COPY` and `ARG`. `build.sh parity` fails the release workflow otherwise.

9. **Package visibility is the owner's decision.** A new GHCR package can start
   private. The chart README says what a cluster needs to pull a private one
   (an `imagePullSecrets` entry for an account with `read:packages`).

## Consequences

- The data directory fix found on the way: both Dockerfiles copied an empty
  0700 directory to `/var/lib/gateon` and the image had it 0755, because COPY
  of a directory creates the destination 0755 and copies only its contents.
  `--chmod=0700` sets it; docker-smoke and `verify` read it back.
- A failed `verify` on a tag fails the workflow after the push: the tags point
  at an image that did not pass. The dry run before tagging is what prevents
  that, as it already is for the binaries.
- The image job depends on the GitHub release existing and being published,
  so a release left as a draft gets no image until it is published and the
  job is dispatched for it.
- `actions/attest-build-provenance` needs a public repository or GitHub
  Enterprise Cloud; if the repository goes private on another plan, that step
  fails (after the push and verify) and must be removed or the plan changed.
