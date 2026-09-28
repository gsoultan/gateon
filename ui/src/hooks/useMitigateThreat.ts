// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../services/client";
import { notifications } from "@mantine/notifications";
import type { MitigateThreatRequest } from "../types/gateon";

// mitigateOrThrow asks for the block and fails when the gateway says it is not
// in force. The API answers a refusal -- a fingerprint named without a network,
// or one inside an operator's release hold -- with success: false and a reason,
// and that used to be shown as a green "Success" carrying the refusal.
export async function mitigateOrThrow(req: MitigateThreatRequest) {
  const res = await api.mitigateThreat({
    source: req.source,
    type: req.type,
    reason: req.reason,
    category: req.category,
  });
  if (!res.success) {
    throw new Error(res.message || `${req.source} was not blocked.`);
  }
  return res;
}

export function useMitigateThreat() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: mitigateOrThrow,
    onSuccess: (data) => {
      notifications.show({
        title: "Blocked",
        message: data.message,
        color: "green",
      });
      queryClient.invalidateQueries({ queryKey: ["security-threats"] });
      queryClient.invalidateQueries({ queryKey: ["diagnostics"] });
    },
    onError: (error: Error) => {
      notifications.show({
        title: "Not blocked",
        message: error.message,
        color: "red",
      });
    },
  });
}
