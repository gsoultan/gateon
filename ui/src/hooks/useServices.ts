import { useQuery } from "@tanstack/react-query";
import { apiFetch, buildQueryString } from "./api";
import type { PaginationParams } from "./api";
import type { ListServicesResponse } from "../types/gateon";

export function useServices(params?: PaginationParams) {
  return useQuery<ListServicesResponse>({
    queryKey: ["services", params],
    queryFn: async () => {
      const res = await apiFetch(`/v1/services${buildQueryString(params)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  });
}
