<!--
Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
SPDX-License-Identifier: MIT
-->

# Gateon Helm chart

> **Prerequisite: there is no published image yet.** Nothing in this repository
> pushes one — `make docker` builds locally, and CI's `docker-smoke` builds and
> inspects without pushing. Until a release publishes to a registry, build and
> push it yourself and point `image.repository` at it:
>
> ```bash
> docker build -t your-registry/gateon:2.6.0 .
> docker push your-registry/gateon:2.6.0
> helm install gateon ./charts/gateon --set image.repository=your-registry/gateon
> ```

```bash
helm install gateon ./charts/gateon
kubectl port-forward svc/gateon-management 8080:8080
```

Then open <http://localhost:8080> and complete setup. Until an administrator
exists the management API answers `503` for everything but setup and the probes.

## Three things worth knowing before you scale it

**`replicaCount > 1` is refused unless you configure an external database and
Redis.** Each replica keeps its own SQLite file, Pebble trace store and ACME
cache on its own volume, so two replicas on the defaults are two gateways that
agree about nothing — a route added through one dashboard is invisible to the
other, and which one a request reaches is the load balancer's decision. Nothing
errors. The chart fails at template time instead, because this is not
recoverable by noticing later.

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
| `replicaCount` | `1` | >1 requires `externalDatabase` and `redis` |
| `profile` | `standard` | `minimal` / `standard` / `enterprise` |
| `resources` | 500m / 256Mi, limit 2Gi | matches the measured 2c/2GB target |
| `memoryLimit` | derived | `GOMEMLIMIT`, 80% of the memory limit |
| `persistence.size` | `10Gi` | traces dominate; see storage-retention.md |
| `secrets.encryptionKey` | generated | min 16 chars |
| `externalDatabase.*` | disabled | rendered into `global.json`, not env |
| `redis.*` | disabled | `REDIS_ADDR` + `global.json` |
| `kubernetesIntegration.gatewayAPI` | `false` | needs the CRDs installed |
| `ebpf.enabled` | `false` | grants NET_ADMIN and BPF |
| `globalConfig` | `{}` | merged into `global.json` |

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
swaps the ClusterRole for a Role.

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

`ebpf.enabled` adds `NET_ADMIN` and `BPF`. That is a real privilege increase on
a process handling hostile traffic, eBPF is marked experimental in the README,
and on most virtualised NICs it attaches at the TC hook rather than native XDP
anyway.

## Upgrading

Read [doc/upgrading.md](../../doc/upgrading.md). For v2.6.0 in particular:
everyone signs out once, and DLP starts inspecting compressed responses with
`dlp_action` defaulting to **block** — which applies to `profile: enterprise`.
