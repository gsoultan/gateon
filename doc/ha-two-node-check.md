# Checking HA failover with two real nodes

`peerOutranks` is unit-tested and proves the rule elects exactly one master
across a pool. That is a statement about a function, not about two processes
converging over a network, and the two are not the same claim: the wire path —
encode, send, receive, authenticate, decide — sits between them.

This is how to exercise it. It needs two hosts with distinct addresses, which is
the part CI cannot provide.

## Why two processes, not two managers in one

A first attempt ran both managers inside one test process with their addresses
faked. It failed, and the failure was the test's fault rather than the code's:
both adverts leave the host with the *same* source address, `peerOutranks`
compares that one address against each node's own, both nodes reach the same
verdict, and both yield. Nobody becomes master.

The comparison only means something when each node really does have its own
address. Two containers is the cheapest way to get that.

## Running it

Build the test binary for the target platform and run one node per container:

```bash
GOOS=linux GOARCH=arm64 go test -c -o ha.test ./internal/ha/

podman network create ha-test

for n in a b; do
  podman run -d --name "ha-$n" --network ha-test --cap-add=NET_ADMIN \
    -v "$PWD:/w:Z" -w /w \
    -e GATEON_HA_INTEGRATION=1 -e GATEON_HA_PRIORITY=100 \
    debian:bookworm-slim \
    ./ha.test -test.run TestSingleNodeElection -test.v -test.timeout=60s
done

sleep 22
podman logs ha-a | grep HA_VERDICT
podman logs ha-b | grep HA_VERDICT
```

Docker works the same way; drop the `:Z` from the volume mount.

## What a correct result looks like

Exactly one `MASTER` and one `BACKUP`, with the higher address winning:

```
HA_VERDICT BACKUP addr=10.89.0.5 priority=100 dropped=0
HA_VERDICT MASTER addr=10.89.0.6 priority=100 dropped=0
```

`dropped=0` on both matters as much as the verdict: it means every advert
authenticated, so the election ran on real traffic rather than on silence. Two
nodes that never hear each other also produce one master each, which looks fine
in isolation and is the failure this is meant to catch.

**Two `MASTER` lines is the split-brain** that ADR 0009 describes. **Two `BACKUP`
lines means the adverts are being exchanged but the tie-break is not resolving** —
check that the two nodes really do have different addresses.

## What the two nodes must share

Electing one master is not enough for the backup to take over as the *same*
gateway. Two nodes on one database still generate their own session key, audit
signature key and proof-of-work secret on first start, and keep them -- with
everything setup writes and every global setting -- in their own
`global.json`. After a failover a session from the old master is refused, a
2FA sign-in fails with "stored under a different session key", and the audit
log may be off (ADR 0056).

So, on both nodes:

1. The same three values in `/etc/default/gateon` (mode 0600, root), next to
   `GATEON_ENCRYPTION_KEY`:

   ```bash
   GATEON_SESSION_KEY=<32 characters, the same on both nodes>
   GATEON_AUDIT_SIGNATURE_KEY=<the same on both nodes>
   GATEON_POW_SECRET=<the same on both nodes>
   ```

2. `global.json` naming them rather than holding values of its own. On a new
   pair, leave the fields out and the environment's are used (and setup writes
   the references). On a pair that already ran, a `global.json` that names its
   own value wins and the gateway logs that it is not using the variable; set
   `auth.paseto_secret` to `$env:GATEON_SESSION_KEY` in Settings on the node
   whose key you keep (that rotates the key and moves the second factors), and
   copy that node's `audit.signature_key` value into `GATEON_AUDIT_SIGNATURE_KEY`
   rather than replacing it, or the stored audit chain stops verifying.

3. Every global-settings change applied to both nodes: copy `global.json` from
   the node you changed. The global settings are per node until they live in
   the database; Redis carries session revocations only (ADR 0012), never
   configuration.

Check it: sign in on the master, stop it, and use the same session on the
backup once it reports `MASTER`. A 401 means the session keys differ.

## The other half

Run it again with `GATEON_HA_PRIORITY` differing between the containers: the
higher priority must win regardless of address. And with a different `AuthPass`
on one node, `TestMismatchedSecretsDoNotFormACluster` shows what a mismatch looks
like — both nodes reporting a rising `dropped` count and neither influencing the
other, which is correct, because they are not in the same cluster.
