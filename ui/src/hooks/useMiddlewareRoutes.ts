// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";
import type { Route } from "../types/gateon";

export function useMiddlewareRoutes(middlewareId: string | null) {
  return useQuery<{ routes: Route[] }>({
    queryKey: ["middleware-routes", middlewareId],
    queryFn: async () => {
      const res = await apiFetch(
        `/v1/middlewares/${encodeURIComponent(middlewareId!)}/routes`
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
    enabled: !!middlewareId,
  });
}
