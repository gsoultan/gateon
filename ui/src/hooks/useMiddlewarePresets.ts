// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";
import type { MiddlewarePreset } from "../types/gateon";

export function useMiddlewarePresets() {
  return useQuery<MiddlewarePreset[]>({
    queryKey: ["middleware-presets"],
    queryFn: async () => {
      const res = await apiFetch("/v1/middlewares/presets");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  });
}
