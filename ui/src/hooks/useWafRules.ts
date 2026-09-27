// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "./api";
import type { WafRule, ListWafRulesResponse, ListWafRulesRequest, CreateWafRuleRequest, UpdateWafRuleRequest } from "../types/gateon";
import { useState } from "react";
import { getApiErrorMessage } from "./api";

/**
 * The body of a successful answer, or an error carrying the gateway's message.
 *
 * Create, update and delete returned resp.json() whatever the status. The
 * gateway answers a rule it refuses -- a regex RE2 cannot compile, a SecLang
 * directive -- with 500 and {"error": ...}, which parsed fine, so the tab
 * announced "WAF Rule created successfully" for a rule that was never stored.
 */
async function okJson(resp: Response): Promise<unknown> {
  if (!resp.ok) {
    throw new Error(getApiErrorMessage(new Error(await resp.text())) || `HTTP ${resp.status}`);
  }
  return resp.json();
}

export function useWafRules(initialParams: ListWafRulesRequest = { pageSize: 10, page: 0 }) {
  const queryClient = useQueryClient();
  const [params, setParams] = useState<ListWafRulesRequest>(initialParams);

  const rulesQuery = useQuery<{ rules: WafRule[]; total: number }>({
    queryKey: ["waf-rules", params],
    queryFn: async () => {
      const queryParams = new URLSearchParams();
      if (params.pageSize !== undefined) queryParams.set("pageSize", params.pageSize.toString());
      if (params.page !== undefined) queryParams.set("page", params.page.toString());
      if (params.search) queryParams.set("search", params.search);
      if (params.category && params.category !== "all") queryParams.set("category", params.category);

      const resp = await apiFetch(`/v1/waf/rules?${queryParams.toString()}`);
      if (!resp.ok) {
        throw new Error(await resp.text());
      }
      const data: ListWafRulesResponse = await resp.json();
      return {
        rules: data.rules || (data as any).Rules || [],
        total: data.total ?? (data as any).Total ?? 0,
      };
    },
  });

  const createMutation = useMutation({
    // The tab reports failures itself; without this the global handler
    // showed a second toast for the same refusal.
    meta: { skipGlobalError: true },
    mutationFn: async (req: CreateWafRuleRequest) => {
      const resp = await apiFetch("/v1/waf/rules", {
        method: "POST",
        body: JSON.stringify(req),
      });
      return okJson(resp);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["waf-rules"] });
    },
  });

  const updateMutation = useMutation({
    meta: { skipGlobalError: true },
    mutationFn: async (req: UpdateWafRuleRequest) => {
      const resp = await apiFetch("/v1/waf/rules", {
        method: "PUT",
        body: JSON.stringify(req),
      });
      return okJson(resp);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["waf-rules"] });
    },
  });

  const deleteMutation = useMutation({
    meta: { skipGlobalError: true },
    mutationFn: async (id: string) => {
      const resp = await apiFetch(`/v1/waf/rules/${id}`, {
        method: "DELETE",
      });
      return okJson(resp);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["waf-rules"] });
    },
  });

  return {
    rules: rulesQuery.data?.rules || [],
    total: rulesQuery.data?.total || 0,
    params,
    setParams,
    isLoading: rulesQuery.isLoading,
    error: rulesQuery.error,
    createRule: createMutation.mutateAsync,
    updateRule: updateMutation.mutateAsync,
    deleteRule: deleteMutation.mutateAsync,
    isCreating: createMutation.isPending,
    isUpdating: updateMutation.isPending,
    isDeleting: deleteMutation.isPending,
  };
}
