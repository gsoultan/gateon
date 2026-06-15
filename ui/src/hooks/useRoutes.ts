import { useQuery, keepPreviousData } from "@tanstack/react-query";
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
    // Keep showing the previous page/results while a new query (e.g. a
    // search keystroke) is in flight. This prevents the list from
    // unmounting into a loading skeleton on every keystroke, which was
    // causing the search inputs to lose focus.
    placeholderData: keepPreviousData,
  });
}
