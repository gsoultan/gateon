// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Code, ConnectError } from "@connectrpc/connect";
import { useInfiniteQuery } from "@tanstack/react-query";
import { api } from "../services/client";
import type { Trace } from "./useTraces";

// The traces whose requests started in a period. The gateway reads the part
// of the period its live store still holds from there, and the part before
// that from the trace archive, so a page here does not know or care which.

/** A period query as the History tab states it. Times are RFC 3339. */
export interface TraceHistoryQuery {
  from: string;
  to: string;
  oldestFirst: boolean;
  /** "", "2xx", "3xx", "4xx", "5xx" or "errors". */
  status: string;
  method: string;
  text: string;
}

export interface TraceHistoryPage {
  traces: Trace[];
  /** Empty once the period has been read to the end. */
  nextCursor: string;
  /** The page stopped at the gateway's scan budget, not because it filled. */
  partial: boolean;
  /** How far through the period the page read, RFC 3339. */
  scannedTo: string;
}

export const HISTORY_PAGE_SIZE = 100;
// The most rows the tab holds at once. The list only grows as pages are
// loaded, and every row is a rendered table row; past this the period should
// be narrowed, which is also the faster way to find anything.
export const HISTORY_MAX_ROWS = 2000;

export async function fetchTraceHistoryPage(q: TraceHistoryQuery, cursor: string): Promise<TraceHistoryPage> {
  const res = await api.queryTraces({
    from: q.from,
    to: q.to,
    limit: HISTORY_PAGE_SIZE,
    cursor,
    oldestFirst: q.oldestFirst,
    status: q.status,
    method: q.method,
    text: q.text,
  });
  return { traces: res.traces, nextCursor: res.nextCursor, partial: res.partial, scannedTo: res.scannedTo };
}

/** Rows loaded so far across the pages of a history query. */
export function loadedRows(pages: TraceHistoryPage[] | undefined): number {
  return (pages ?? []).reduce((n, p) => n + p.traces.length, 0);
}

/**
 * retryUnlessAnswered retries a failed trace query once, as the dashboard does
 * any query -- unless the gateway answered: a period it refused, a trace it no
 * longer has, or a search already running will get the same answer again.
 */
export function retryUnlessAnswered(failures: number, err: unknown): boolean {
  if (err instanceof ConnectError && [Code.InvalidArgument, Code.NotFound, Code.ResourceExhausted].includes(err.code)) {
    return false;
  }
  return failures < 1;
}

/**
 * useTraceHistory pages through a period. It stops offering another page at
 * HISTORY_MAX_ROWS, and does not poll: a period in the past does not change,
 * and the Live tab is where the present is watched.
 *
 * It opts out of the dashboard's keepPreviousData: the rows of the period
 * searched last, shown under the caption of the one searched now while it
 * loads, would read as its answer.
 */
export function useTraceHistory(q: TraceHistoryQuery | null) {
  return useInfiniteQuery({
    queryKey: ["trace-history", q],
    queryFn: ({ pageParam }) => fetchTraceHistoryPage(q as TraceHistoryQuery, pageParam),
    initialPageParam: "",
    getNextPageParam: (last, all) =>
      last.nextCursor && loadedRows(all) < HISTORY_MAX_ROWS ? last.nextCursor : undefined,
    enabled: q !== null,
    refetchOnWindowFocus: false,
    placeholderData: undefined,
    retry: retryUnlessAnswered,
  });
}
