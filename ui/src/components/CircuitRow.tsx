import { useMemo } from "react";
import { Table, Text, Badge } from "@mantine/core";
import { useRouteStats } from "../hooks/useGateon";

export type CircuitState = "all" | "CLOSED" | "OPEN" | "HALF-OPEN";

export interface CircuitRowProps {
  routeId: string;
  routeName: string;
  stateFilter: CircuitState;
}

export function CircuitRow({
  routeId,
  routeName,
  stateFilter,
}: CircuitRowProps) {
  const { data: stats, isLoading } = useRouteStats(routeId);

  const rows = useMemo(() => {
    if (!stats || stats.length === 0) return [];
    return stats
      .map((s) => ({
        url: s.url,
        alive: s.alive,
        circuit:
          (s as { circuit_state?: string }).circuit_state ??
          (s.alive ? "CLOSED" : "OPEN"),
        errors: s.error_count,
        reqs: s.request_count,
      }))
      .filter(
        (r) => stateFilter === "all" || r.circuit === stateFilter
      );
  }, [stats, stateFilter]);

  if (isLoading) return null;
  if (rows.length === 0) return null;

  return (
    <>
      {rows.map((r) => (
        <Table.Tr key={r.url}>
          <Table.Td>
            <Text size="sm" fw={600}>
              {routeName || routeId}
            </Text>
            <Text size="xs" c="dimmed">
              {routeId}
            </Text>
          </Table.Td>
          <Table.Td>
            <Text size="xs" truncate maw={200}>
              {r.url}
            </Text>
          </Table.Td>
          <Table.Td>
            <Badge
              color={
                r.circuit === "CLOSED"
                  ? "green"
                  : r.circuit === "HALF-OPEN"
                    ? "yellow"
                    : "red"
              }
              variant="light"
            >
              {r.circuit}
            </Badge>
          </Table.Td>
          <Table.Td>
            <Text size="xs">{r.reqs}</Text>
          </Table.Td>
          <Table.Td>
            <Text size="xs" c={r.errors > 0 ? "red" : undefined}>
              {r.errors}
            </Text>
          </Table.Td>
        </Table.Tr>
      ))}
    </>
  );
}
