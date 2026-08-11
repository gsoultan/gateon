// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../services/client";
import { useRealTimeStore } from "../store/useRealTimeStore";
import type { GetDiagnosticsResponse } from "../types/gateon";

export function useDiagnostics() {
  const queryClient = useQueryClient();
  const subscribe = useRealTimeStore((s: any) => s.subscribe);
  const queryKey = ["diagnostics"];

  const query = useQuery<GetDiagnosticsResponse>({
    queryKey,
    queryFn: async () => {
      const res = await api.getDiagnostics({});
      return res as any;
    },
  });

  useEffect(() => {
    return subscribe("/v1/diagnostics/watch", (newData: GetDiagnosticsResponse) => {
      queryClient.setQueryData(queryKey, newData);
    });
  }, [queryClient, queryKey, subscribe]);

  return query;
}
