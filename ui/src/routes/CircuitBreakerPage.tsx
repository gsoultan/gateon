import { useMemo } from "react";
import {
  Card,
  Title,
  Text,
  Stack,
  Group,
  Badge,
  Table,
  Center,
  Skeleton,
} from "@mantine/core";
import { IconCircuitSwitchClosed, IconAlertTriangle } from "@tabler/icons-react";
import { useRoutes } from "../hooks/useGateon";
import { useRouteStats } from "../hooks/useGateon";

function CircuitRow({ routeId, routeName }: { routeId: string; routeName: string }) {
  const { data: stats, isLoading } = useRouteStats(routeId);

  const rows = useMemo(() => {
    if (!stats || stats.length === 0) return [];
    return stats.map((s) => ({
      url: s.url,
      alive: s.alive,
      circuit: (s as { circuit_state?: string }).circuit_state ?? (s.alive ? "CLOSED" : "OPEN"),
      errors: s.error_count,
      reqs: s.request_count,
    }));
  }, [stats]);

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
              color={r.circuit === "CLOSED" ? "green" : r.circuit === "HALF-OPEN" ? "yellow" : "red"}
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

export default function CircuitBreakerPage() {
  const { data, isLoading } = useRoutes({ page_size: 100 });

  const routes = data?.routes ?? [];
  const openCount = 0; // Would need to aggregate from stats

  return (
    <Stack gap="lg">
      <Group justify="space-between">
        <div>
          <Title order={2} fw={800} style={{ letterSpacing: -1 }}>
            Circuit Breaker
          </Title>
          <Text c="dimmed" size="sm" fw={500}>
            Monitor circuit states across route targets. CLOSED = healthy, OPEN = failing, HALF-OPEN = testing recovery.
          </Text>
        </div>
        <Group>
          <Badge size="lg" variant="light" color="green" leftSection={<IconCircuitSwitchClosed size={14} />}>
            Closed
          </Badge>
          <Badge size="lg" variant="light" color="red" leftSection={<IconAlertTriangle size={14} />}>
            Open / Half-Open
          </Badge>
        </Group>
      </Group>

      <Card shadow="xs" padding="lg" radius="lg" withBorder>
        {isLoading ? (
          <Skeleton h={200} />
        ) : routes.length === 0 ? (
          <Center py={60}>
            <Text c="dimmed">No routes configured. Create routes to see circuit states.</Text>
          </Center>
        ) : (
          <Table verticalSpacing="md" withRowBorders highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Route</Table.Th>
                <Table.Th>Target URL</Table.Th>
                <Table.Th>Circuit State</Table.Th>
                <Table.Th>Requests</Table.Th>
                <Table.Th>Errors</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {routes.map((r) => (
                <CircuitRow key={r.id} routeId={r.id} routeName={r.name || r.id} />
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Card>
    </Stack>
  );
}
