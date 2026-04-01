import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";
import type { ClientAuthority, GlobalConfig } from "../types/gateon";

export function useClientAuthorities() {
  return useQuery<ClientAuthority[]>({
    queryKey: ["client_authorities"],
    queryFn: async () => {
      const res = await apiFetch("/v1/global");
      if (!res.ok) throw new Error(await res.text());
      const config: GlobalConfig = await res.json();
      return config.tls?.client_authorities || [];
    },
  });
}
