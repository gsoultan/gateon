import { useQuery } from "@tanstack/react-query";
import { apiFetch, buildQueryString } from "./api";
import type { RouteListParams } from "./api";
import type { ListRoutesResponse } from "../types/gateon";

export function useRoutes(params?: RouteListParams) {
  return useQuery<ListRoutesResponse>({
    queryKey: ["routes", params],
    queryFn: async () => {
      const res = await apiFetch(`/v1/routes${buildQueryString(params)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  });
}
