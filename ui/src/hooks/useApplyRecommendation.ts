import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "./api";

export interface ApplyRecommendationRequest {
  anomaly_type: string;
  source: string;
  threat_id?: string;
}

export interface ApplyRecommendationResponse {
  success: boolean;
  message: string;
}

export function useApplyRecommendation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (req: ApplyRecommendationRequest) => {
      const response = await apiFetch<ApplyRecommendationResponse>("/gateon.v1.ApiService/ApplyRecommendation", {
        method: "POST",
        body: JSON.stringify(req),
      });
      return response;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["security-threats"] });
      queryClient.invalidateQueries({ queryKey: ["reputations"] });
      queryClient.invalidateQueries({ queryKey: ["gateon-config"] });
      queryClient.invalidateQueries({ queryKey: ["diagnostics"] });
    },
  });
}
