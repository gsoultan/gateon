// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Stack, Text, Badge, Group, Tooltip } from "@mantine/core";
import { useNetwork } from "@mantine/hooks";
import { useGateonStatus } from "../hooks/useGateon";
import { useRealTimeStore } from "../store/useRealTimeStore";
import { IconBolt, IconBoltOff } from "@tabler/icons-react";

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
  const isRealTimeConnected = useRealTimeStore((state) => state.isConnected);
  const conn = deriveConnection(online, isFetching, isError, status?.status);

  return (
    <Group gap="xs">
      <Tooltip label={isRealTimeConnected ? "Real-time stream active" : "Real-time stream disconnected"}>
        {isRealTimeConnected ? (
          <IconBolt size={14} color="var(--mantine-color-green-filled)" />
        ) : (
          <IconBoltOff size={14} color="var(--mantine-color-red-filled)" />
        )}
      </Tooltip>
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
    </Group>
  );
}
