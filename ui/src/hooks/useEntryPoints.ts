// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useQuery } from "@tanstack/react-query";
import { apiFetch, buildQueryString } from "./api";
import type { PaginationParams } from "./api";
import type { ListEntryPointsResponse } from "../types/gateon";

export function useEntryPoints(params?: PaginationParams) {
  return useQuery<ListEntryPointsResponse>({
    queryKey: ["entryPoints", params],
    queryFn: async () => {
      const res = await apiFetch(`/v1/entryPoints${buildQueryString(params)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      return {
        entryPoints: json.entryPoints || json.entry_points || [],
        totalCount: json.totalCount ?? json.total_count ?? 0,
        page: json.page ?? 1,
        pageSize: json.pageSize ?? json.page_size ?? 10,
      };
    },
  });
}
