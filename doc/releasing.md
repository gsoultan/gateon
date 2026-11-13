# Releasing

How a Gateon release is signed, and how to look after the key it is signed
with. The build itself is `.github/workflows/release.yml`; this page covers the
part a person has to do. The decision behind it is
[ADR 0085](adr/0085-a-gateway-learns-of-a-new-release-from-a-signed-list.md).

## What is signed

Every release publishes `checksums.txt`, which names the SHA-256 of each
archive, package and SBOM, and `checksums.txt.sig`, an Ed25519 signature over
that list. A gateway checking for a newer release fetches both and believes the
list only if the signature verifies under a public key compiled into that
gateway from `internal/selfupdate/release_keys.txt`.

So there are two halves, kept in two places:

| Half | Where it lives | Who can read it |
| :--- | :--- | :--- |
| Private key | The `GATEON_RELEASE_SIGNING_KEY` repository secret, and one offline copy | The release workflow on a tag push; the maintainer |
| Public key | `internal/selfupdate/release_keys.txt`, committed | Everyone |

The private key is never committed, never pasted into an issue or a chat, and
never handed to a CI job other than the tag build. The dry run of the release
workflow does not receive it: it signs with a key it throws away.

## Creating the release key (once)

On your own machine, from a checkout of `main`:

```bash
go run ./scripts/releasesign keygen -out ~/gateon-release.key
```

It writes the private key to that file (mode 0600, and it refuses to overwrite
an existing file) and prints one line, the public key. Then:

1. Add the printed line to `internal/selfupdate/release_keys.txt`, open a pull
   request with only that change, and merge it.
2. Store the private key as a repository secret:

   ```bash
   gh secret set GATEON_RELEASE_SIGNING_KEY --repo gsoultan/gateon < ~/gateon-release.key
   ```

3. Move `~/gateon-release.key` somewhere offline (a password manager, an
   encrypted drive) and delete it from the working machine. That copy is the
   only way to keep signing if the secret is ever cleared; GitHub does not show
   a secret back.

From the first tag after the merge, the release is signed, the workflow fails
before publishing if the secret is missing or does not match a committed key,
and gateways built from that tag refuse a release list that is not signed.

Releases cut before a key is committed are published unsigned, with a warning
in the workflow run, and gateways show their version as not verified.

## Checking a release by hand

```bash
gh release download v1.8.3 --repo gsoultan/gateon -p checksums.txt -p checksums.txt.sig
go run ./scripts/releasesign verify -in checksums.txt -sig checksums.txt.sig
sha256sum --check --ignore-missing checksums.txt
```

`verify` uses the keys of the checkout it runs from, exactly as a gateway built
from that checkout would.

## Rotating the key

A gateway accepts a signature from any key it was built with, so rotation is
two releases, not one:

1. Run `keygen` again for the new key. Add its public line to
   `release_keys.txt` *below* the old one and merge.
2. Cut a release, still signed with the **old** key. Gateways that upgrade to
   it now trust both.
3. Replace the secret with the new private key. Later releases are signed with
   it.
4. Once every version you still support carries the new key, remove the old
   line.

A gateway that skipped the release in step 2 does not trust the new key and
will report later releases as failing verification. It is upgraded by hand
once, by package or archive, after which it is current.

## If the key is lost or exposed

**Lost** (the secret was cleared and there is no offline copy): there is no way
to sign a release that installed gateways accept. Create a new key as above.
Installed gateways will say the newest release failed verification until they
are upgraded by hand to a version built with the new key. Say so in that
release's notes.

**Exposed** (the private key may have been read by anyone else): treat every
release list as untrusted until gateways stop accepting the old key. Create a
new key, remove the old line from `release_keys.txt` in the same change, cut a
release signed with the new key, and announce that upgrading to it must be done
by hand and verified with the commands above. Do not sign the transition
release with the exposed key.

## Mirrors

A gateway can read releases from somewhere other than GitHub
(`GATEON_UPDATE_SOURCE`, or Settings, Updates). The mirror serves two files,
byte for byte as published:

```
<source>/latest/download/checksums.txt
<source>/latest/download/checksums.txt.sig
```

A mirror cannot forge a release: it does not hold the key. It can only withhold
one, by continuing to serve an older signed list.
