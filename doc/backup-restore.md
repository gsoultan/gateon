<!--
Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
SPDX-License-Identifier: MIT
-->

# Backup and restore

What to copy, in what order, and how to prove the copy is usable before you need
it to be.

Read the first section even if you skip the rest. Most of what follows is
ordinary file and database copying; **`GATEON_ENCRYPTION_KEY` is the part that
loses data silently**, because it is the only thing on the list that is not a
file and will not appear in any backup that copies files.

## The encryption key is not in the backup

When `GATEON_ENCRYPTION_KEY` is set, gateon encrypts five fields with AES-256-GCM
before writing them to the global config, each stored as `enc:` followed by
base64:

| Field | What it is |
| :--- | :--- |
| `auth.paseto_secret` | signs every management session token |
| `auth.database_url` | may embed the database password |
| `auth.database_config.password` | the database password |
| `geoip.maxmind_license_key` | MaxMind licence |
| `security_advanced.pow.secret` | proof-of-work challenge signing |

The key itself is read from the environment and stored nowhere. A backup of the
config file, the database and the whole data directory therefore contains all
five as ciphertext and nothing that can open them. Restore onto a host without
the same key and gateon cannot sign a session, cannot reach its own database,
and cannot verify a challenge it issued.

**Store it wherever you keep credentials that are not this system's** — a
password manager or a secrets manager, not the backup volume. A key kept next to
the ciphertext it opens is not protecting anything.

**Check it is actually taking effect.** A key shorter than 16 characters is
rejected and secrets are written in **cleartext** instead:

```
GATEON_ENCRYPTION_KEY is set but too short, so secrets are NOT being encrypted
```

That line is logged once per process. The failure is quiet by design — returning
the plaintext rather than refusing to start means a typo'd key produces a working
gateway whose config file contains the paseto secret and the database password in
the clear. Grep your config for `"enc:` after setting the key; if the sensitive
fields are readable, the key did not apply.

## What to back up

Paths below use `$DATA_DIR` and `$CONFIG_DIR`, which resolve in this order:

- **`$DATA_DIR`** — `GATEON_DATA_DIR`, else `GATEON_STATE_DIR`, else
  `/var/lib/gateon` if it exists (Linux), else the working directory.
- **The global config file** is `GLOBAL_CONFIG_FILE` if set, and otherwise
  `global.json` **relative to the working directory**. Note it is used as given
  rather than searched for, so `GATEON_CONFIG_DIR` does not move it — that
  variable steers other lookups. The packaged systemd unit sets
  `GLOBAL_CONFIG_FILE=/etc/gateon/global.json`, so a deb/rpm install has it
  there; a container or a hand-run binary has it wherever the process started.

If you are unsure which file is live, gateon logs `path` and `config_dir` at
startup when the file is missing, and the running config is whatever
`GLOBAL_CONFIG_FILE` names. Confirm before you back up: a backup of the
`global.json` nobody reads restores a gateway to defaults, with the WAF off.

| # | What | Where | Losing it costs you |
| :-- | :--- | :--- | :--- |
| 1 | Encryption key | `GATEON_ENCRYPTION_KEY` (environment) | every encrypted secret, permanently |
| 2 | Global config | `$GLOBAL_CONFIG_FILE`, else `./global.json` | all global settings: WAF, tiers, auth, TLS, telemetry |
| 3 | Config database | `$DATA_DIR/gateon.db` (SQLite default) or the external DSN | routes, services, entrypoints, middlewares, users, API keys, ACME certificates, audit log |
| 4 | Certificates | `$DATA_DIR/certs/` (or `GATEON_TLS_CACHE_DIR`) | uploaded certificates, and the ACME cache when Redis is not configured — a restore re-issues from Let's Encrypt and can hit rate limits |
| 5 | Audit archives | `$DATA_DIR/audit/` | compliance history: WAF audit logs and the compressed archives the retention job writes |

**Redis, if configured**, holds the ACME cache under `gateon:acme:` and
rate-limit counters. The counters are ephemeral and want no backup. The ACME
cache is worth keeping for the same rate-limit reason as (4); if Redis is
configured it is used *instead of* the on-disk cache, not in addition.

### What is deliberately not on the list

`$DATA_DIR/telemetry_pebble/` holds one record per request — access logs and
traces. It is the largest thing on disk by a wide margin and it is *derived
observability data*: losing it costs you history, not function. Back it up only
if you have a retention obligation that names it, and size the job accordingly.
See [storage-retention.md](storage-retention.md).

## Taking a backup

### SQLite (the default)

**Do not `cp gateon.db`.** The database runs in WAL mode
(`journal_mode(WAL)`), so committed transactions live in `gateon.db-wal` until a
checkpoint folds them in. A plain copy of the `.db` alone can be missing recent
writes or be torn mid-checkpoint, and it will restore without complaining.

Use SQLite's own backup, which is consistent against a running gateway:

```bash
sqlite3 "$DATA_DIR/gateon.db" ".backup '/backup/gateon-$(date +%F).db'"
```

`VACUUM INTO` also works and compacts as it goes:

```bash
sqlite3 "$DATA_DIR/gateon.db" "VACUUM INTO '/backup/gateon-$(date +%F).db'"
```

Then the files, which can be copied normally:

```bash
tar czf "/backup/gateon-files-$(date +%F).tar.gz" \
  -C "$(dirname "${GLOBAL_CONFIG_FILE:-./global.json}")" "$(basename "${GLOBAL_CONFIG_FILE:-global.json}")" \
  -C "$DATA_DIR" certs audit
```

### Postgres

The database is external, so back it up with that engine's tooling on its own
schedule — `pg_dump`. Items 2, 4 and 5 still live on the gateway's
disk and still need the `tar` above; a database dump alone is not a backup of
gateon.

## Restoring

Order matters: the gateway reads its config at startup and its database
immediately after.

1. **Stop gateon.** Restoring underneath a running process gives you a mixture of
   both states.
2. **Set `GATEON_ENCRYPTION_KEY`** to the value that was in effect when the backup
   was taken. Not the current one, if those differ — the ciphertext in the backup
   is only openable by the key that wrote it.
3. **Restore the files**, preserving ownership and mode. `certs/` is created
   `0700` and should stay that way.
4. **Restore the database.** For SQLite, copy the backup into place as
   `$DATA_DIR/gateon.db` and remove any stale `gateon.db-wal` and `gateon.db-shm`
   beside it — they belong to the database you replaced, not the one you restored.
5. **Start gateon** and work through the verification below.

### Restoring onto a different host

Two things that surprise people:

**Sessions do not survive**, and should not. Session tokens are signed with
`auth.paseto_secret`; if the restored host has a different one, every existing
token is refused. That is correct behaviour, not a restore failure — everyone
signs in again.

**Check what the config says about addresses.** `global.json` carries the
management entrypoint's bind address and allowlist. Restoring a production config
onto a staging box republishes production's management surface on staging's
address.

## Verifying the restore

A backup is a hypothesis until a restore is tested. Run these against the
restored instance; each one fails distinctly if a different item on the list is
missing.

| Check | Proves |
| :--- | :--- |
| Sign in to the dashboard | The paseto secret decrypted — so `GATEON_ENCRYPTION_KEY` matches and item 1 is right |
| `GET /v1/routes` returns your routes | The config database restored (item 3) |
| Global settings show your tier and WAF config | `global.json` restored (item 2) |
| A TLS route serves without re-issuing | `certs/` restored (item 4) |
| Send a request that your WAF blocks | The chain is built from restored config, not defaults |

**The first check is the one that matters most**, because it is the only one that
fails specifically when the encryption key is wrong. Everything else can pass
against a config whose secrets are unopenable ciphertext — the gateway starts,
serves the dashboard's login page, and refuses every credential. If sign-in
fails after a restore and the password is definitely right, suspect the key
before you suspect the database.

Test a restore onto a scratch host on a schedule. An untested backup and no
backup differ only in how long it takes to find out.
