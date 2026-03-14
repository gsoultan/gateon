import { useQuery } from "@tanstack/react-query";
import { apiFetch, buildQueryString } from "./api";
import type { PaginationParams } from "./api";
import type { ListTLSOptionsResponse } from "../types/gateon";

export function useTLSOptions(params?: PaginationParams) {
  return useQuery<ListTLSOptionsResponse>({
    queryKey: ["tlsoptions", params],
    queryFn: async () => {
      const res = await apiFetch(`/v1/tls-options${buildQueryString(params)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  });
}
