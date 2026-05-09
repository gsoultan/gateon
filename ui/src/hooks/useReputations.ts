import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";
import type { Reputation } from "../types/gateon";

export interface ListReputationsResponse {
  reputations: Reputation[];
}

export function useReputations(limit: number = 50) {
  return useQuery<ListReputationsResponse>({
    queryKey: ["reputations", limit],
    queryFn: async () => {
      const res = await apiFetch(`/v1/security/reputations?limit=${limit}`);
      if (!res.ok) {
        throw new Error(await res.text());
      }
      return res.json();
    },
    refetchInterval: 10000, // Refresh every 10 seconds
  });
}
