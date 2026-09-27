# 23. The trace archive has a directory per node, and every node reads them all

Date: 2026-09-27

## Status

Accepted. Amends the layout in [ADR 0022](0022-traces-are-archived-an-hour-at-a-time.md)
before its first release.

## Context

ADR 0022 archives each gateway's traces into its own `trace_archive/`. Behind a
load balancer, a request lands on one of several gateways, so the trace an
operator is looking for is in one node's archive -- and the dashboard, which
talks to one node, searched only that node's. ADR 0022 said to give each node
its own directory if the archive sat on shared storage, because two nodes
writing one directory replace each other's hours; nothing enforced it, and
nothing read the other directories if someone did.

Two ways to see the whole cluster:

- **Ask the other nodes.** A query fans out over the network to each peer's
  management API. That needs every node to know every other, and a credential a
  node may use against its peers -- a new trust boundary between gateways, for
  a read-only view.
- **Share the storage.** The archive is plain files. With its root on storage
  every node mounts -- NFS, EFS, a CSI volume -- each node can read the others'
  files directly, provided no two nodes ever write the same one.

## Decision

**Every node writes only its own directory under the archive root, and reads
every node's.**

```
<archive root>/<node>/2026/09/26/traces-2026-09-26T14Z.<node>.ndjson.zst
```

- **The node's name** is `GATEON_NODE_NAME`, or the host name when that is not
  set, lower-cased, reduced to letters, digits, `.`, `_` and `-`, at most 63
  characters. Two gateways on one host that share an archive root must each be
  given a name: by host name they would share a directory, and replace each
  other's hours -- the failure the Redis invalidator's process-level node ID
  exists to avoid.
- **The name is in the file name as well as the directory.** A file copied out
  of the tree -- a download is exactly that -- still says which node's traces
  it holds, and two nodes' copies of one hour do not collide in a downloads
  folder. The period stays first, so `traces-2026-09-26T*` still selects a day.
  The header records the node too.
- **A search merges every node's traces into one timeline.** The local store
  answers above its hot floor and the local archive below it, as before; every
  other node's archive answers for the whole period, because this node cannot
  see the others' stores. The sources are merged by trace key -- the same key the
  cursor holds -- so pages neither repeat nor skip across nodes. A trace in the
  results names the node it came from.
- **Retention is applied to the whole root by every node.** A node that is
  renamed or replaced -- a pod rescheduled under a new name -- leaves its
  directory behind, and someone has to age it out. With every node applying the
  same settings, the deletions agree; a file another node already removed is
  not an error. The size budget is the whole archive's, oldest hours first,
  whichever node wrote them.
- **Without shared storage nothing changes** but the extra directory level: a
  root with one node in it is searched exactly as before.

## Consequences

- A cluster whose archive root is shared sees every node's archived traces from
  any node's dashboard. Recent traces -- an hour and a few minutes, until they
  are archived -- are visible only on the node that served them.
- Nodes sharing a root must agree on retention and size settings; the most
  aggressive one wins. The documentation says so.
- Every gateway that can write the shared root can make the others read what
  it wrote, so another node's file gets no more trust than a damaged one of this
  node's: the header, the checksummed index and frames that must tile the hour
  are checked before anything is decoded, and traces are rendered as text.
- A search holds a file's index and one frame per node with hours in its period
  -- about a megabyte each -- and at most 64 MiB in all. A frame is counted by
  the size its header states, which the decoder holds it to, before it is
  decoded. A search that would go past the limit is refused, not cut short: a
  page that quietly left out a node's traces would read as the whole answer.
  Lookups and downloads decode one frame at a time, under the decoder's own
  ceiling.
- Opening a trace tries this node's file for its hour first, then the others'.
  A file that cannot be read does not stop the rest being tried; its error is
  reported only if no node has the trace.
- The archive's counts on the dashboard -- hours, bytes, nodes -- are as of this
  node's last retention pass, which follows every file it writes and runs at
  least hourly. The list of hours is read from the disk on each request.
- Two nodes' traces with the same key -- the same ID, starting in the same
  nanosecond -- are the one case the cursor cannot tell apart: a page that ends
  between them skips the second. An ID is the request's `X-Request-ID`, so this
  takes a client sending one ID to two nodes in the same nanosecond.
- The layout changed before the archive was released, so no archive has to be
  moved.

## Alternatives considered

- **Fan-out over the management API** -- rejected above: a new trust boundary
  between gateways for a view the filesystem already gives.
- **The node in the directory only.** Shorter names, but a downloaded file would
  not say which node it came from, and two nodes' downloads of one hour share a
  name.
- **A process-level identity, like the invalidator's.** It changes on every
  restart, so each restart would start a new directory and a node's own hours
  would no longer be its own to reconcile.
