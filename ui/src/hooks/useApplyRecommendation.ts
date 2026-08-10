// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../services/client";

export interface ApplyRecommendationRequest {
  anomalyType: string;
  source: string;
  threatId?: string;
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
        anomalyType: req.anomalyType,
        source: req.source,
        threatId: req.threatId,
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
