import { useQuery } from "@tanstack/react-query";
import { apiFetch, buildQueryString } from "./api";
import type { PaginationParams } from "./api";
import type { ListMiddlewaresResponse } from "../types/gateon";

export function useMiddlewares(params?: PaginationParams) {
  return useQuery<ListMiddlewaresResponse>({
    queryKey: ["middlewares", params],
    queryFn: async () => {
      const res = await apiFetch(`/v1/middlewares${buildQueryString(params)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  });
}
