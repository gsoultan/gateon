// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useQuery } from "@tanstack/react-query";
import { api } from "../services/client";
import type { Reputation } from "../types/gateon";

export interface ListReputationsResponse {
  reputations: Reputation[];
}

export function useReputations(limit: number = 50) {
  return useQuery<ListReputationsResponse>({
    queryKey: ["reputations", limit],
    queryFn: async () => {
      const res = await api.listReputations({ limit });
      return {
        reputations: res.reputations as any,
      };
    },
    refetchInterval: 10000, // Refresh every 10 seconds
  });
}
