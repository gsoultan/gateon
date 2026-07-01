import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "./api";
import { WafRule, ListWafRulesResponse, CreateWafRuleRequest, UpdateWafRuleRequest, DeleteWafRuleRequest } from "../types/gateon";

export function useWafRules() {
  const queryClient = useQueryClient();

  const rulesQuery = useQuery<WafRule[]>({
    queryKey: ["waf-rules"],
    queryFn: async () => {
      const resp = await apiFetch("/v1/waf/rules");
      const data: ListWafRulesResponse = await resp.json();
      return data.rules || [];
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
    rules: rulesQuery.data || [],
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
