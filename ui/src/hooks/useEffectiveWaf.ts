// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";
import type { EffectiveWafView } from "../utils/wafEffective";

export type { EffectiveWaf, EffectiveWafView, WafMode } from "../utils/wafEffective";
export { routeSwitchOn } from "../utils/wafEffective";

export const EFFECTIVE_WAF_QUERY_KEY = ["waf-effective"] as const;

export function useEffectiveWaf() {
  return useQuery<EffectiveWafView>({
    queryKey: EFFECTIVE_WAF_QUERY_KEY,
    queryFn: async () => {
      const resp = await apiFetch("/v1/waf/effective");
      if (!resp.ok) throw new Error((await resp.text()) || `HTTP ${resp.status}`);
      return (await resp.json()) as EffectiveWafView;
    },
  });
}
