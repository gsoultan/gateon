import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../services/client";
import { notifications } from "@mantine/notifications";
import type { RemoveMitigatedThreatRequest } from "../types/gateon";

export function useRemoveMitigation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (req: RemoveMitigatedThreatRequest) => api.removeMitigatedThreat({
      source: req.source,
      ja4plus: req.ja4plus,
    }),
    onSuccess: (data: any) => {
      notifications.show({
        title: "Success",
        message: data.message,
        color: "green",
      });
      queryClient.invalidateQueries({ queryKey: ["security-threats"] });
      queryClient.invalidateQueries({ queryKey: ["diagnostics"] });
    },
    onError: (error: Error) => {
      notifications.show({
        title: "Error",
        message: error.message,
        color: "red",
      });
    },
  });
}
