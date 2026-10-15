// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Badge, Tooltip } from "@mantine/core";
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
    <Tooltip
      label={`Gateway ${conn.label.toLowerCase()} · real-time stream ${isRealTimeConnected ? "active" : "disconnected"}`}
    >
      <Badge
        size="lg"
        radius="xl"
        variant="light"
        color={conn.color}
        leftSection={isRealTimeConnected ? <IconBolt size={13} /> : <IconBoltOff size={13} />}
        aria-label={`Connection status: ${conn.label}`}
        styles={{ root: { textTransform: "none", fontSize: 12 } }}
      >
        {conn.label.charAt(0) + conn.label.slice(1).toLowerCase()}
      </Badge>
    </Tooltip>
  );
}
