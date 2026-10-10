<!--
Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
SPDX-License-Identifier: MIT
-->

# Gateon Helm chart

```bash
helm install gateon ./charts/gateon
kubectl port-forward svc/gateon-management 8080:8080
```

Then open <http://localhost:8080> and complete setup. Until an administrator
exists the management API answers `503` for everything but setup and the probes.

## The image

By default the chart runs `ghcr.io/gsoultan/gateon:<appVersion>` (`image.tag`
empty means the chart's `appVersion`, `1.1.0`). The release workflow publishes
it for every release tag, for `linux/amd64` and `linux/arm64`: the binary is
copied out of the release's own tarball, checked against the release's
`checksums.txt`, onto `distroless/static:nonroot`, so it is byte-for-byte the
binary in `gateon_<version>_linux_<arch>.tar.gz` (CGO-free, PGO, uid 65532).
Each image carries an SBOM and a provenance attestation
([ADR 0065](../../doc/adr/0065-the-published-image-is-the-release-tarballs-binary.md)).

Tags: `X.Y.Z` always; `X.Y` for the newest patch of that line; `latest` for
the release GitHub marks Latest. A prerelease gets only its exact version. For
production, pin the digest the release's workflow summary prints:

```bash
helm install gateon ./charts/gateon --set image.tag=1.1.0@sha256:<digest>
gh attestation verify oci://ghcr.io/gsoultan/gateon:1.1.0 --owner gsoultan
```

**Pulling it may need credentials.** Whether the GHCR package is public is the
repository owner's decision, made in the package's settings; GHCR can create
a new package private. While it is private, a cluster needs a pull secret for
a GitHub account that can read the package (a token with `read:packages`):

```bash
kubectl create secret docker-registry ghcr-pull \
  --docker-server=ghcr.io --docker-username=<github-user> --docker-password=<token>
helm install gateon ./charts/gateon --set 'imagePullSecrets[0].name=ghcr-pull'
```

Without it the pod sits in `ImagePullBackOff` with `denied` or `unauthorized`
in its events. A `manifest unknown` instead means that release's image was
never published: v1.1.0 predates the publishing workflow and gets its image
when the owner runs it for that tag.

**Building your own** is still supported, for a private registry, a patched
build or an air-gapped cluster. The repository's `Dockerfile` builds from
source (UI, proto, eBPF, PGO, `-trimpath`, CGO off) for whichever platforms
you name:

```bash
docker buildx build --platform linux/amd64,linux/arm64 --build-arg VERSION=1.1.0 \
  -t your-registry/gateon:1.1.0 --push .
helm install gateon ./charts/gateon --set image.repository=your-registry/gateon --set image.tag=1.1.0
```

It is the same runtime image -- the release workflow fails if the two
Dockerfiles' runtime stages differ -- but not the same binary as the release
tarball's unless you build it from the tag with the release's Go toolchain.

## Four things worth knowing before you rely on it

**`replicaCount > 1` is refused** ([ADR 0056](../../doc/adr/0056-replicas-of-one-gateway-share-one-identity.md)).
Each replica keeps its own `global.json` on its own volume, and `global.json`
holds what setup writes and every global setting saved in the dashboard. An
external database and Redis share the routes, users and session revocations,
but not that: setup on one replica turned authentication and the audit log on
for that replica only, and each dashboard save reached whichever replica served
it. The chart used to allow it with `externalDatabase` and `redis` set; it now
fails at template time whatever they say, because this is not recoverable by
noticing later. See [High availability](#high-availability) for what is
supported. `kubectl scale` bypasses the check; do not.

**The gateway's identity is in the release's Secret.** The session key (which
signs dashboard sessions and encrypts stored second factors), the audit log's
signature key and the proof-of-work secret are generated once into
`<release>-secrets` (`session-key`, `audit-signature-key`, `pow-secret`) and
read by the pod as `GATEON_SESSION_KEY`, `GATEON_AUDIT_SIGNATURE_KEY` and
`GATEON_POW_SECRET`. Gateon used to generate them per volume, so with
persistence off every restart signed everyone out and locked every 2FA account
out. Like the encryption key they are reused on every upgrade and kept on
uninstall. An install whose `global.json` already names its own keys keeps
them, and logs that it is not using the Secret's (ADR 0056 says how to adopt
them).

**The encryption key is not in any backup.** `GATEON_ENCRYPTION_KEY` encrypts
the paseto secret, the database URL and password, the MaxMind key and the
proof-of-work secret. It lives only in the Secret this chart creates. Copy it
somewhere you keep credentials before you configure anything —
[doc/backup-restore.md](../../doc/backup-restore.md) has the rest.

A generated key is reused across upgrades: the template looks up the existing
Secret rather than minting a new one, because a new key cannot decrypt what the
old one wrote. `helm uninstall` followed by a fresh install *is* a new key, and
the old data is unreadable.

**A key under 16 characters is rejected by the runtime and the secrets are then
written in cleartext** — warned once, otherwise indistinguishable from success.
The chart refuses one outright.

## global.json lives on the volume, and is seeded once

Setup writes `global.json` -- the session key, `auth.enabled`, the management
bind -- and so does every save of global settings in the dashboard. The chart
used to mount it read-only from a Secret at `/etc/gateon`, so setup failed with
`read-only file system` and a fresh install could never finish it.

The gateway now keeps `global.json` on the data volume
(`GLOBAL_CONFIG_FILE=<persistence.mountPath>/global.json`). The Secret is still
mounted at `/etc/gateon`, and its `global.json` -- `globalConfig` with
`externalDatabase` and `redis` rendered in -- **seeds** the one on the volume
the first time the volume has none (`GATEON_GLOBAL_CONFIG_SEED`). After that the
copy on the volume is what the gateway reads, so changing `globalConfig`,
`externalDatabase` or `redis` on an existing install does not reach it; change
those settings in the dashboard. The seed starts the audit log on, signed, as
setup does; `globalConfig.audit` overrides it.

**With `externalDatabase`, setup keeps that database.** The wizard shows the
database the configuration names and offers no other; `POST /v1/setup` naming a
different one is refused (ADR 0057). To use another database, change
`externalDatabase` before the first start, or `global.json` on the volume and
restart, before running setup.

## Persistence off

With `persistence.enabled=false` the data directory is an `emptyDir`, so every
pod start is on a fresh one:

- **Global settings are the seed again.** Whatever was saved in the dashboard
  since -- the WAF, alerting, the management allowlist -- is gone; put what must
  survive a restart in `globalConfig`. The audit log comes back on.
- **Sessions and second factors survive**, because the identity is the
  Secret's, not the volume's. (Before ADR 0056 every restart signed everyone out
  and locked every 2FA account out.)
- **With `externalDatabase`** the routes and users are in the database, setup
  does **not** reopen, and the gateway marks itself set up again at start
  because the database holds an administrator.
- **Without `externalDatabase`** the SQLite database is on the `emptyDir` too:
  every restart is a new, empty gateway, and first-run setup is open again,
  behind a new setup token (in the pod log).
- Traces, the ACME cache (unless Redis holds it) and audit archives are lost.

## High availability

One replica. On Kubernetes, availability comes from the StatefulSet
rescheduling the pod, not from a second replica: a second replica is a second
gateway until the global settings live in the shared database (ADR 0056's
option (a), not built). The identity in the Secret is what a future
multi-replica chart needs and is already shared; the global settings are what
is missing.

On hosts, the two-node VRRP failover is supported with the shared identity set
on both nodes; see [doc/ha-two-node-check.md](../../doc/ha-two-node-check.md).

## Entrypoints are seeded once

`entrypoints` renders `entrypoints.json`, so the ports the Service publishes are
ports the gateway actually binds. Without that the Service forwards to a
container that is not listening and requests time out with nothing in the log to
explain it.

**It is seeded onto a fresh database only.** After the first start the database
is authoritative and the dashboard is where entrypoints change, so editing this
value on an existing install does nothing. That is gateon's model rather than a
chart limitation, but a values change that silently no-ops is worth knowing
about in advance.

## Configuration

| Key | Default | |
| :--- | :--- | :--- |
| `replicaCount` | `1` | >1 is refused (ADR 0056) |
| `profile` | `standard` | `minimal` / `standard` / `enterprise` |
| `resources` | 500m / 256Mi, limit 2Gi | matches the measured 2c/2GB target |
| `memoryLimit` | derived | `GOMEMLIMIT`, 80% of the memory limit |
| `persistence.size` | `10Gi` | traces dominate; see storage-retention.md |
| `secrets.encryptionKey` | generated | min 16 chars |
| `secrets.existingSecret` | none | `encryption-key`; and `session-key`, `audit-signature-key`, `pow-secret` (required with persistence off) |
| `persistence.enabled` | `true` | off: see [Persistence off](#persistence-off) |
| `externalDatabase.*` | disabled | rendered into `global.json`, not env |
| `redis.*` | disabled | `REDIS_ADDR` + `global.json` |
| `kubernetesIntegration.gatewayAPI` | `false` | needs the CRDs installed |
| `ebpf.enabled` | `false` | runs the container as uid 0 with only NET_ADMIN and BPF |
| `ebpf.hostNetwork` | `false` | attaches to the node's NIC instead of the pod's interface |
| `globalConfig` | `{}` | seeds `global.json` on a volume that has none |

### Why the database is not configured through environment variables

Gateon reads **no** database environment variable. `internal/db.AuthDatabaseURL`
builds the DSN from `auth.database_config`, then `auth.database_url`, then
`auth.sqlite_path` — all of them in `global.json`. An env-var-shaped chart would
leave every replica on SQLite while looking configured.

The keys are snake_case because the file is parsed with `encoding/json` against
the generated protobuf structs, so the `json:` tags govern.
`TestHelmRenderedGlobalConfigParsesIntoEveryFieldItSets` in `internal/config`
pins that contract.

### Kubernetes integration

The controller starts whenever `KUBERNETES_SERVICE_HOST` is set, so it is always
on in-cluster. It is **read-only** against the API — it watches Ingress and
HTTPRoute and writes only into gateon's own stores — so the role grants
`get, list, watch` and nothing else. No `ingresses/status`, no events, no leases:
they would be unused authority on a component that terminates hostile traffic.

Set `kubernetesIntegration.watchNamespace` to scope it to one namespace, which
swaps the ClusterRole for a Role and sets `GATEON_K8S_WATCH_NAMESPACE` so the
controller lists only there — before that variable existed it listed every
namespace, the Role refused it, and nothing synced.

`gatewayAPI` is **off by default**. The controller waits for both informers to
sync and the Gateway one never will without its CRDs, so the client retries in a
loop and fills the log. Ingress handling is unaffected either way.

## Security defaults

The image is `distroless/static:nonroot`, and the chart makes that explicit:
`runAsNonRoot`, uid 65532, `readOnlyRootFilesystem`, all capabilities dropped,
`RuntimeDefault` seccomp. `/tmp` is an `emptyDir` because the read-only root
still needs one.

The management API is on its own ClusterIP Service. A single LoadBalancer
carrying both it and the traffic ports would publish the dashboard on the same
address as the proxy, and the management allowlist ships as `0.0.0.0/0`.

`ebpf.enabled` runs the container as uid 0 with every capability dropped except
`NET_ADMIN` and `BPF`. Those two are what loading and attaching the programs
needs, and uid 0 is how they reach the process: neither Docker nor Kubernetes
gives added capabilities to any other user, so the non-root image with the two
added was refused eBPF. That is a real privilege increase on a process handling
hostile traffic, and eBPF is marked experimental in the README. Turn eBPF on in
gateon's settings as well; the chart grants the privileges and nothing else.
See [ADR 0018](../../doc/adr/0018-ebpf-privileges-are-capabilities.md).

Without `ebpf.hostNetwork` the programs attach to the pod's own interface and
filter traffic to this pod, still before gateon sees it. With it they attach to
the node's NIC -- on EKS the ENA interface, where they fall back to the TC hook
-- and every container port becomes a port on the node. On most virtualised NICs
eBPF attaches at the TC hook rather than native XDP.

## Upgrading

Read [doc/upgrading.md](../../doc/upgrading.md). For v2.6.0 in particular:
everyone signs out once, and DLP starts inspecting compressed responses with
`dlp_action` defaulting to **block** — which applies to `profile: enterprise`.
