// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";
import type { ClientAuthority, GlobalConfig } from "../types/gateon";

export function useClientAuthorities() {
  return useQuery<ClientAuthority[]>({
    queryKey: ["clientAuthorities"],
    queryFn: async () => {
      const res = await apiFetch("/v1/global");
      if (!res.ok) throw new Error(await res.text());
      const config: GlobalConfig = await res.json();
      return config.tls?.clientAuthorities || (config as any)?.tls?.client_authorities || [];
    },
  });
}
