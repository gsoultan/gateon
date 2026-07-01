import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "./api";
import type { WafRule, ListWafRulesResponse, ListWafRulesRequest, CreateWafRuleRequest, UpdateWafRuleRequest } from "../types/gateon";
import { useState } from "react";

export function useWafRules(initialParams: ListWafRulesRequest = { limit: 10, offset: 0 }) {
  const queryClient = useQueryClient();
  const [params, setParams] = useState<ListWafRulesRequest>(initialParams);

  const rulesQuery = useQuery<{ rules: WafRule[]; total: number }>({
    queryKey: ["waf-rules", params],
    queryFn: async () => {
      const queryParams = new URLSearchParams();
      if (params.limit) queryParams.set("limit", params.limit.toString());
      if (params.offset) queryParams.set("offset", params.offset.toString());
      if (params.search) queryParams.set("search", params.search);

      const resp = await apiFetch(`/v1/waf/rules?${queryParams.toString()}`);
      const data: ListWafRulesResponse = await resp.json();
      return {
        rules: data.rules || [],
        total: data.total || 0,
      };
    },
  });

  const createMutation = useMutation({
    mutationFn: async (req: CreateWafRuleRequest) => {
      const resp = await apiFetch("/v1/waf/rules", {
        method: "POST",
        body: JSON.stringify(req),
      });
      return resp.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["waf-rules"] });
    },
  });

  const updateMutation = useMutation({
    mutationFn: async (req: UpdateWafRuleRequest) => {
      const resp = await apiFetch("/v1/waf/rules", {
        method: "PUT",
        body: JSON.stringify(req),
      });
      return resp.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["waf-rules"] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const resp = await apiFetch(`/v1/waf/rules/${id}`, {
        method: "DELETE",
      });
      return resp.json();
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
