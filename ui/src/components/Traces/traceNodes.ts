// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Gateways that share the trace archive's storage each archive under their own
// name, and a search reads all of them (ADR-0023). Which gateway recorded a
// trace is worth a column only when there is more than one.

/** severalNodes says whether the items came from more than one gateway. */
export function severalNodes(items: readonly { node?: string }[]): boolean {
  return items.some((i) => (i.node ?? "") !== (items[0].node ?? ""));
}

/**
 * archivePath is where an archived hour's file is under the archive root: in
 * the directory of the gateway that wrote it, then of the UTC day it holds --
 * gw-1/2026/09/26/traces-2026-09-26T14Z.gw-1.ndjson.zst.
 */
export function archivePath(segment: { node: string; periodStart: string; name: string }): string {
  return `${segment.node}/${segment.periodStart.slice(0, 10).replace(/-/g, "/")}/${segment.name}`;
}
