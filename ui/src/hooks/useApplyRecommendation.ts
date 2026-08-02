import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../services/client";

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
      const res = await api.applyRecommendation({
        anomalyType: req.anomaly_type,
        source: req.source,
        threatId: req.threat_id,
      });
      return res as ApplyRecommendationResponse;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["security-threats"] });
      queryClient.invalidateQueries({ queryKey: ["reputations"] });
      queryClient.invalidateQueries({ queryKey: ["gateon-config"] });
      queryClient.invalidateQueries({ queryKey: ["diagnostics"] });
    },
  });
}
