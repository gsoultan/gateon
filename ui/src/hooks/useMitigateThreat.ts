import { useMutation, useQueryClient } from "@tanstack/react-query";
import { mitigateThreat } from "./api";
import { notifications } from "@mantine/notifications";
import type { MitigateThreatRequest } from "../types/gateon";

export function useMitigateThreat() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (req: MitigateThreatRequest) => mitigateThreat(req),
    onSuccess: (data) => {
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
