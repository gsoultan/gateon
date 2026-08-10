// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useQuery } from "@tanstack/react-query";
import { queryClient } from "../queryClient";
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
  }, queryClient);
}
