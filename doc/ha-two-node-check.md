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

## The other half

Run it again with `GATEON_HA_PRIORITY` differing between the containers: the
higher priority must win regardless of address. And with a different `AuthPass`
on one node, `TestMismatchedSecretsDoNotFormACluster` shows what a mismatch looks
like — both nodes reporting a rising `dropped` count and neither influencing the
other, which is correct, because they are not in the same cluster.
