import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";
import type { GlobalConfig } from "../types/gateon";

export function useGateonConfig() {
  return useQuery<GlobalConfig>({
    queryKey: ["config"],
    queryFn: async () => {
      const res = await apiFetch("/v1/global");
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    },
  });
}
