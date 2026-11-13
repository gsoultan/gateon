# 85. A gateway learns of a new release from a signed list

Date: 2026-11-13

## Status

Accepted. First of three: this record covers finding out that a release
exists. Installing one, and handing the listening sockets to it, are separate
decisions with their own records.

## Context

Gateon had no way to learn that a newer release existed. An operator found out
by watching the repository, and a gateway that had fallen several versions
behind looked exactly like a current one. For software whose job is to stand
between the internet and everything else, "nobody noticed there was a fix" is
the usual way a known vulnerability stays exploitable.

The obvious remedy, asking GitHub what the latest release is, makes the answer
only as trustworthy as the path it came over. A release's `checksums.txt` was
published unsigned, so anything that could answer for the release source (a
mirror, a compromised account, a TLS-intercepting proxy) could name any
version. That matters little while the gateway only displays a number, and
completely once it installs what the number points to, which is the next
change in this series. The trust has to be right before anything is built on
it.

The gateway also cannot be the thing that runs a general-purpose updater.
ADR 0019 keeps the service from writing its own binary, and the image is
`distroless/static` with nothing to shell out to.

## Decision

**Each release publishes `checksums.txt.sig`, an Ed25519 signature over
`checksums.txt`, and a gateway believes a release list only when that signature
verifies under a public key compiled into the gateway.**

- **What is signed.** `checksums.txt` already names the SHA-256 of every other
  file of the release, so one signature covers all of them. The signed message
  is the list prefixed with `gateon-release-checksums-v1\n`, so the key's
  signature over a list is never a valid signature over anything else it may
  one day sign. The signature file is one base64 line.
- **How.** `crypto/ed25519` on both sides: `scripts/releasesign` in the release
  build, `internal/selfupdate` in the gateway, sharing one implementation. No
  cosign, gpg or minisign binary, so nothing is added to the image and the
  build stays CGO-free. The private key lives only in the
  `GATEON_RELEASE_SIGNING_KEY` repository secret; the public keys live in
  `internal/selfupdate/release_keys.txt`, one per line, and several lines are a
  rotation in progress.
- **What the gateway fetches.** `<source>/latest/download/checksums.txt` and
  `.sig`, at most 256 KiB and 1 KiB, over https (http only to loopback), through
  a dialer that refuses the management listener and cloud metadata addresses,
  following only redirects that pass the same rule. The version is read from
  the archive names inside the signed list (`gateon_<version>_linux_<arch>.tar.gz`),
  never from an unsigned field, a header or a redirect.
- **Where from.** `https://github.com/gsoultan/gateon/releases` unless
  `GlobalConfig.update.source_url` or `GATEON_UPDATE_SOURCE` names a mirror laid
  out the same way. The source is an administrator-only setting: it decides
  where the gateway makes requests from inside the network.
- **How often.** About a minute after start, then every
  `TierDefaults.UpdateCheckInterval` (24h on every tier), each spread by up to
  a tenth. `GATEON_UPDATE_CHECK_INTERVAL` overrides it within 1h to 30d.
  **Check now** is refused more often than once in 30 seconds per source.
- **Off switches.** `GlobalConfig.update.check_disabled`, and
  `GATEON_UPDATE_CHECK=false`, which wins over the setting for a host that must
  never call out.
- **What it does with the answer.** Shows it: Settings, Updates; a header
  notice for every signed-in role; the `gateon_update_available` gauge. Nothing
  is downloaded or installed by this change.
- **Who may do what.** Reading the status needs `diagnostics:read`. Making the
  gateway check needs `global:write`, on REST (`POST /v1/update/check`),
  Connect and gRPC alike.

**Failing closed.** A list whose signature does not verify, or that the gateway
cannot parse, is refused and any version learned earlier is dropped: the
dashboard says the check failed and names no version. An unreachable source
keeps the last verified answer and says how old it is.

**Before a key exists.** `release_keys.txt` ships empty. A build with no key
cannot verify anything, so it reports the newest version it read as
*unverified*, in those words, and the release workflow publishes unsigned with
a warning. Both branches exist only for that interval. Once a key is committed
the workflow refuses to release without a signature that key verifies, and the
gateway refuses a list without one. The key is created by the maintainer on
their own machine; no build, CI job or agent session ever holds the private
half outside the secret.

## Consequences

- **A new default outbound request.** An upgraded gateway makes two small GETs
  to github.com once a day. It sends no identifier, version or configuration;
  the request is the same from every gateway. It is on by default because a
  gateway that never learns of a security release is the larger risk, and it is
  listed in `doc/upgrading.md` with both ways to turn it off.
- **An air-gapped gateway** logs nothing alarming: the check fails as
  unreachable, at most once a day, and Settings says so. Turning it off, or
  pointing it at an internal mirror, removes even that.
- **The release key becomes something to look after.** Losing it means
  committing a new key and shipping a release signed with the old one, or, if
  the old one is gone, a release that installed gateways will not recognise
  and that has to be installed by hand once. `doc/releasing.md` covers
  creation, rotation and loss.
- **Containers and Kubernetes are told, not upgraded.** The gateway detects how
  it was installed and shows the pull command or Helm value to change. That
  stays true after the install work lands: an image is replaced by whatever
  started it.
- **Bounded cost.** One goroutine with a context, one timer, an HTTP client
  with two idle connections, a status held in one atomic pointer. Nothing on
  the request path.

## Alternatives considered

- **The GitHub releases API.** Structured, but unsigned, rate-limited per
  address, and it ties a mirror to imitating GitHub's API instead of serving
  two static files.
- **cosign / Sigstore keyless.** Stronger provenance (the image already has a
  Sigstore attestation, ADR 0065), but verifying it in the gateway means
  embedding a trust root and a large dependency tree, or shelling out to a
  binary the image does not have. A pinned Ed25519 key is the smallest thing
  that answers "did the project publish this list".
- **Trusting TLS to github.com alone.** Fails for every mirror, and makes any
  party that can terminate that TLS a party that can name a release.
- **Off by default.** Leaves the gateways that most need telling, the ones
  nobody is watching, untold.
