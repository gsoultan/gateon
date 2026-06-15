import { Stack, Text, Badge } from "@mantine/core";
import { useNetwork } from "@mantine/hooks";
import { useGateonStatus } from "../hooks/useGateon";

type Connection = {
  label: string;
  color: string;
};

/** Derives a human-readable connection state from network + backend status. */
function deriveConnection(
  online: boolean,
  isFetching: boolean,
  isError: boolean,
  status?: string,
): Connection {
  if (!online) return { label: "OFFLINE", color: "red" };
  if (isError) return { label: "RECONNECTING", color: "yellow" };
  if (status === "running") return { label: "LIVE", color: "green" };
  if (isFetching) return { label: "CONNECTING", color: "yellow" };
  return { label: status?.toUpperCase() || "OFFLINE", color: "red" };
}

/**
 * ConnectionStatus surfaces real-time trust in the dashboard's "live" data by
 * combining the browser's network state with the backend status poll. It
 * reassures users when streams are healthy and clearly flags reconnection.
 */
export function ConnectionStatus() {
  const { online } = useNetwork();
  const { data: status, isFetching, isError } = useGateonStatus();
  const conn = deriveConnection(online, isFetching, isError, status?.status);

  return (
    <Stack gap={0} align="flex-end">
      <Text size="xs" fw={700} c="dimmed" lh={1}>
        STATUS
      </Text>
      <Badge
        size="sm"
        color={conn.color}
        variant="dot"
        styles={{ root: { border: 0 } }}
        aria-label={`Connection status: ${conn.label}`}
      >
        {conn.label}
      </Badge>
    </Stack>
  );
}
