import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";
import type { Certificate, GlobalConfig } from "../types/gateon";

export function useCertificates() {
  return useQuery<{ certificates: Certificate[] }>({
    queryKey: ["certificates"],
    queryFn: async () => {
      const res = await apiFetch("/v1/global");
      if (!res.ok) throw new Error(await res.text());
      const config: GlobalConfig = await res.json();
      return { certificates: config.tls?.certificates || [] };
    },
  });
}
