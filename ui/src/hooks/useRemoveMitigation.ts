import { useMutation, useQueryClient } from "@tanstack/react-query";
import { removeMitigatedThreat } from "./api";
import { notifications } from "@mantine/notifications";

export function useRemoveMitigation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (args: { source: string; ja4h?: string }) => removeMitigatedThreat(args.source, args.ja4h),
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
