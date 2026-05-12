import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getDiagnostics, getApiUrl } from "./api";
import type { GetDiagnosticsResponse } from "../types/gateon";

export function useDiagnostics() {
  const queryClient = useQueryClient();
  const queryKey = ["diagnostics"];

  const query = useQuery<GetDiagnosticsResponse>({
    queryKey,
    queryFn: getDiagnostics,
  });

  useEffect(() => {
    const url = getApiUrl("/v1/diagnostics/watch");
    const eventSource = new EventSource(url, { withCredentials: true });

    eventSource.onmessage = (event) => {
      try {
        const newData = JSON.parse(event.data) as GetDiagnosticsResponse;
        queryClient.setQueryData(queryKey, newData);
      } catch (err) {
        console.error("Failed to parse diagnostics SSE", err);
      }
    };

    return () => {
      eventSource.close();
    };
  }, [queryClient, queryKey]);

  return query;
}
