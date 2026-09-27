// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useInfiniteQuery } from "@tanstack/react-query";
import { api } from "../services/client";
import { getApiUrl } from "./api";

// The trace archive: one compressed file per UTC hour of traces and gateway,
// named for the hour it holds and the node that wrote it
// (traces-2026-09-26T14Z.gw-1.ndjson.zst). Gateways sharing the archive's
// storage each write their own and list everyone's (ADR-0023). Sizes and
// counts are int64s, which arrive as bigint; they are numbers here because the
// page does arithmetic on them.

export interface TraceArchiveSegment {
  name: string;
  periodStart: string;
  periodEnd: string;
  sizeBytes: number;
  traceCount: number;
  archivedAt: string;
  node: string;
}

export interface TraceArchiveStatus {
  enabled: boolean;
  traceStoreActive: boolean;
  retentionDays: number;
  maxSizeBytes: number;
  segmentCount: number;
  totalSizeBytes: number;
  oldestPeriod: string;
  newestPeriod: string;
  lastArchivedAt: string;
  lastError: string;
  lastErrorAt: string;
  /** This gateway's name in the archive. */
  node: string;
  /** Every node with an archived hour, this one among them once it has one. */
  nodes: string[];
}

export interface TraceArchivePage {
  segments: TraceArchiveSegment[];
  nextPageToken: string;
  status: TraceArchiveStatus | null;
}

// Two days of hours a page.
export const ARCHIVE_PAGE_SIZE = 48;

export async function fetchTraceArchivePage(pageToken: string): Promise<TraceArchivePage> {
  const res = await api.listTraceArchives({ pageSize: ARCHIVE_PAGE_SIZE, pageToken });
  const st = res.status;
  return {
    segments: res.segments.map((s) => ({
      name: s.name,
      periodStart: s.periodStart,
      periodEnd: s.periodEnd,
      sizeBytes: Number(s.sizeBytes),
      traceCount: Number(s.traceCount),
      archivedAt: s.archivedAt,
      node: s.node,
    })),
    nextPageToken: res.nextPageToken,
    status: st
      ? {
          enabled: st.enabled,
          traceStoreActive: st.traceStoreActive,
          retentionDays: st.retentionDays,
          maxSizeBytes: Number(st.maxSizeBytes),
          segmentCount: Number(st.segmentCount),
          totalSizeBytes: Number(st.totalSizeBytes),
          oldestPeriod: st.oldestPeriod,
          newestPeriod: st.newestPeriod,
          lastArchivedAt: st.lastArchivedAt,
          lastError: st.lastError,
          lastErrorAt: st.lastErrorAt,
          node: st.node,
          nodes: [...st.nodes],
        }
      : null,
  };
}

/** useTraceArchives lists the archived hours newest first, a page at a time. */
export function useTraceArchives() {
  return useInfiniteQuery({
    queryKey: ["trace-archives"],
    queryFn: ({ pageParam }) => fetchTraceArchivePage(pageParam),
    initialPageParam: "",
    getNextPageParam: (last) => last.nextPageToken || undefined,
  });
}

/**
 * traceArchiveDownloadUrl is where an archived hour downloads from: the file as
 * stored (zstd), or decompressed to NDJSON for a machine with no zstd. A plain
 * link, so the browser streams it to disk instead of the page holding it.
 */
export function traceArchiveDownloadUrl(name: string, plain: boolean): string {
  return getApiUrl(`/v1/traces/archives/${encodeURIComponent(name)}${plain ? "?format=ndjson" : ""}`);
}
