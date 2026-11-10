# Local development

`make dev` runs a complete gateway on your machine with sample config loaded, so
the dashboard has entrypoints, routes, services and middleware to show from the
first page load.

```bash
brew install container jq     # Apple's container CLI (macOS 15+, Apple silicon)
container system start        # once per boot
make dev                      # or: scripts/dev.sh
```

| What | Where |
| :--- | :--- |
| Dashboard | <http://localhost:8080> — sign in as **admin / admin** |
| Proxy | <http://localhost:8000> |
| Database | PostgreSQL 18 in the Apple container `gateon-dev-pg`, on `127.0.0.1:55432` |
| Local state | `dev/.data/` (gitignored) |

Ctrl-C stops gateon and the sample backends. Postgres keeps running so the next
start is instant.

## The dev accounts

| Account | Password | Role |
| :--- | :--- | :--- |
| `admin` | `admin` | administrator |
| `operator` | `operator` | operator |
| `viewer` | `viewer` | viewer |

**These are for local development only.** Nothing about them reaches a real
install:

- The password policy (ADR 0050) is unchanged. Every API that sets a password —
  REST, gRPC and the dashboard — still refuses `admin`, and the shipped binary
  has no switch to allow it.
- `dev/seed` is the only thing that writes these passwords, and it writes the
  hash itself rather than going through the API. It does that only when the
  database is plainly a developer's: a SQLite file under a `dev/.data`
  directory, or a Postgres URL whose host is `127.0.0.1`, `::1` or `localhost`.
  Pointed anywhere else it refuses before touching a row. `dev/seed` is not part
  of `cmd/gateon` and is not in any release artifact.
- `dev/global.json` binds the dashboard to `127.0.0.1` and allows only loopback
  clients, and the Postgres container publishes its port on `127.0.0.1` only.

To use a password of your own for all three accounts, set
`GATEON_DEV_PASSWORD`. A password of 12 characters or more that the policy
accepts is stored through the normal API, and the database-location check does
not apply.

```bash
GATEON_DEV_PASSWORD='correct-horse-battery' make dev
```

## Options

| Command | Does |
| :--- | :--- |
| `make dev` | Postgres in an Apple container (the default) |
| `make dev-sqlite` | SQLite at `dev/.data/gateon-dev.db`, no container needed |
| `make dev DEV_FLAGS=--clean` | start from an empty database (destroys and recreates the container) |
| `make dev DEV_FLAGS=--ui` | rebuild the dashboard first |
| `make dev-pg-down` | stop the Postgres container, keep its data |
| `make dev-pg-destroy` | delete the Postgres container and its data |
| `scripts/dev-postgres.sh psql` | a `psql` shell on the dev database |

`scripts/dev-postgres.sh` reads `GATEON_PG_NAME`, `GATEON_PG_IMAGE`,
`GATEON_PG_PORT`, `GATEON_PG_USER`, `GATEON_PG_PASSWORD`, `GATEON_PG_DB` and
`GATEON_PG_TIMEOUT` if you need to move it; `scripts/dev-postgres.sh -h` lists
the defaults.

## The sample config

Everything lives in `dev/*.json` and is loaded through the same file-backed
stores a real install uses, so it is also a working reference for the file
formats.

| Route | Rule | Service | Middleware |
| :--- | :--- | :--- | :--- |
| `host-route` | ``Host(`whoami.localhost`)`` | `whoami-service` | request ID, security headers (recommended), compression |
| `api-route` | ``PathPrefix(`/api`)`` | `api-service` | route WAF, rate limit, in-flight cap, circuit breaker, strip `/api`, CORS |
| `canary-route` | ``PathPrefix(`/canary`)`` | `canary-service` | retry, strip `/canary` |
| `web-route` | ``PathPrefix(`/`)`` | `whoami-service` | response header, CORS |

The three services point at small echo backends (`dev/backend`) the script
starts on `127.0.0.1:9001` (whoami), `:9002` (api) and `:9003` (canary).
`canary-service` sends about 90% of requests to whoami and 10% to canary.

```bash
curl http://localhost:8000/                          # whoami backend
curl http://whoami.localhost:8000/                   # host-based route
curl http://localhost:8000/api/anything              # api backend, /api stripped
for i in $(seq 20); do curl -s http://localhost:8000/canary/ | jq -r .backend; done | sort | uniq -c
curl 'http://localhost:8000/api/x?id=1%27+OR+1=1'    # the WAF answers 403
```

WAF blocks from `127.0.0.1` are not recorded as Security Hub threats, because
loopback is trusted. Send traffic from another host to populate it.
