// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";
import { useApiConfigStore } from "../store/useApiConfigStore";
import type { PathStats } from "../types/gateon";

const queryKey = ["path-stats"];

interface PathStatsOptions {
  /**
   * Refresh on the dashboard's refresh interval while the caller is mounted.
   * Only the Path Metrics table asks: the shell's health bar reads this query
   * on every page, and the endpoint aggregates the whole retention window.
   */
  live?: boolean;
}

/**
 * Per host and path request counts and latency.
 *
 * This used to fetch once and then wait for a `pathMetrics` field on the live
 * metrics stream. The gateway has never sent one -- the snapshot carries
 * golden signals, not a table that can run to thousands of rows -- so the
 * Path Metrics page showed the moment it was opened, and a path first served
 * a second before that was missing until the page was reloaded.
 */
export function usePathStats({ live = false }: PathStatsOptions = {}) {
  const refreshIntervalSec = useApiConfigStore((s) => s.refreshInterval);
  return useQuery<PathStats[]>({
    queryKey,
    queryFn: async () => {
      const res = await apiFetch("/v1/diag/path-stats");
      // The body, not the status: QueryError shows getApiErrorMessage of it,
      // which reads the gateway's {"error": ...} rather than "HTTP 500".
      if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
      return res.json();
    },
    refetchInterval: live ? refreshIntervalSec * 1000 : false,
  });
}
