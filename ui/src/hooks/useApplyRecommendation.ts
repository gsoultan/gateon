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
      const response = await apiFetch("/gateon.v1.ApiService/ApplyRecommendation", {
        method: "POST",
        body: JSON.stringify(req),
      });
      if (!response.ok) {
        throw new Error(await response.text());
      }
      return response.json() as Promise<ApplyRecommendationResponse>;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["security-threats"] });
      queryClient.invalidateQueries({ queryKey: ["reputations"] });
      queryClient.invalidateQueries({ queryKey: ["gateon-config"] });
      queryClient.invalidateQueries({ queryKey: ["diagnostics"] });
    },
  });
}
