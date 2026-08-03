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
      const json = await res.json();
      const opts = json.tlsOptions || json.options || json.tls_options || [];
      return {
        tlsOptions: opts,
        options: opts,
        totalCount: json.totalCount ?? json.total_count ?? 0,
        page: json.page ?? 1,
        pageSize: json.pageSize ?? json.page_size ?? 10,
      } as ListTLSOptionsResponse;
    },
  });
}
