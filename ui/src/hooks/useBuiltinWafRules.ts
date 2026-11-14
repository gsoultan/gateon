// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";
import type { BuiltinWafRule, ListBuiltinWafRulesResponse } from "../types/gateon";

export type BuiltinWafRulesParams = {
  page: number;
  pageSize: number;
  search: string;
  category: string;
};

export type BuiltinWafRulesPage = {
  rules: BuiltinWafRule[];
  total: number;
  categories: string[];
};

/**
 * One page of the rules compiled into the gateway.
 *
 * They change only when the gateway is upgraded, so a page is kept for five
 * minutes. The dashboard's defaults already keep the previous page on screen
 * while the next one loads.
 */
export function useBuiltinWafRules(params: BuiltinWafRulesParams) {
  return useQuery<BuiltinWafRulesPage>({
    queryKey: ["waf-rules-builtin", params],
    staleTime: 5 * 60 * 1000,
    queryFn: async () => {
      const query = new URLSearchParams({
        page: params.page.toString(),
        pageSize: params.pageSize.toString(),
      });
      if (params.search) query.set("search", params.search);
      if (params.category && params.category !== "all") query.set("category", params.category);

      const resp = await apiFetch(`/v1/waf/rules/builtin?${query.toString()}`);
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}`);
      }
      const data: ListBuiltinWafRulesResponse = await resp.json();
      return {
        rules: data.rules ?? [],
        total: data.total ?? 0,
        categories: data.categories ?? [],
      };
    },
  });
}
