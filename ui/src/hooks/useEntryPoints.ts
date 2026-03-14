import { useQuery } from "@tanstack/react-query";
import { apiFetch, buildQueryString } from "./api";
import type { PaginationParams } from "./api";
import type { ListEntryPointsResponse } from "../types/gateon";

export function useEntryPoints(params?: PaginationParams) {
  return useQuery<ListEntryPointsResponse>({
    queryKey: ["entrypoints", params],
    queryFn: async () => {
      const res = await apiFetch(`/v1/entrypoints${buildQueryString(params)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  });
}
