import { useMutation, useQueryClient } from "@tanstack/react-query";
import { removeMitigatedThreat } from "./api";
import { notifications } from "@mantine/notifications";

export function useRemoveMitigation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (source: string) => removeMitigatedThreat(source),
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
