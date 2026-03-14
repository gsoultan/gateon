import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";
import type { IsSetupRequiredResponse } from "../types/gateon";

export function useIsSetupRequired() {
  return useQuery<IsSetupRequiredResponse>({
    queryKey: ["setup-required"],
    queryFn: async () => {
      const res = await apiFetch("/v1/setup/required");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
    retry: false,
  });
}
