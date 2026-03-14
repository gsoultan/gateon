import { useMemo, useState } from "react";
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
  Select,
  SimpleGrid,
  Paper,
} from "@mantine/core";
import {
  IconCircuitSwitchClosed,
  IconAlertTriangle,
  IconCircleCheck,
  IconLoader2,
} from "@tabler/icons-react";
import { useRoutes, useRouteStats, useAggStats } from "../hooks/useGateon";

type CircuitState = "all" | "CLOSED" | "OPEN" | "HALF-OPEN";

function CircuitRow({
  routeId,
  routeName,
  stateFilter,
}: {
  routeId: string;
  routeName: string;
  stateFilter: CircuitState;
}) {
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
        (r) =>
          stateFilter === "all" || r.circuit === stateFilter
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

export default function CircuitBreakerPage() {
  const { data, isLoading } = useRoutes({ page_size: 100 });
  const { data: aggStats } = useAggStats();
  const [stateFilter, setStateFilter] = useState<CircuitState>("all");

  const routes = data?.routes ?? [];
  const closed = aggStats?.healthy_targets ?? 0;
  const open = aggStats?.open_circuits ?? 0;
  const halfOpen = aggStats?.half_open_circuits ?? 0;

  return (
    <Stack gap="lg">
      <Group justify="space-between" wrap="wrap">
        <div>
          <Title order={2} fw={800} style={{ letterSpacing: -1 }}>
            Circuit Breaker
          </Title>
          <Text c="dimmed" size="sm" fw={500}>
            Monitor circuit states across route targets. CLOSED = healthy,
            OPEN = failing, HALF-OPEN = testing recovery.
          </Text>
        </div>
        <Group gap="md">
          <Select
            size="xs"
            w={140}
            label="Filter by state"
            value={stateFilter}
            onChange={(v) => setStateFilter((v as CircuitState) ?? "all")}
            data={[
              { value: "all", label: "All states" },
              { value: "CLOSED", label: "Closed" },
              { value: "OPEN", label: "Open" },
              { value: "HALF-OPEN", label: "Half-Open" },
            ]}
          />
          <Stack gap={4}>
            <Group gap="xs">
              <Badge
                size="sm"
                variant="light"
                color="green"
                leftSection={<IconCircuitSwitchClosed size={12} />}
              >
                Closed
              </Badge>
              <Badge
                size="sm"
                variant="light"
                color="red"
                leftSection={<IconAlertTriangle size={12} />}
              >
                Open / Half-Open
              </Badge>
            </Group>
          </Stack>
        </Group>
      </Group>

      <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="md">
        <Paper
          p="md"
          radius="lg"
          withBorder
          style={{
            borderLeftWidth: 4,
            borderLeftColor: "var(--mantine-color-green-6)",
          }}
        >
          <Group gap="sm">
            <IconCircleCheck size={28} color="var(--mantine-color-green-6)" />
            <div>
              <Text size="xs" c="dimmed" fw={700}>
                CLOSED
              </Text>
              <Text size="xl" fw={800} c="green.6">
                {closed}
              </Text>
              <Text size="xs" c="dimmed">
                Healthy targets
              </Text>
            </div>
          </Group>
        </Paper>
        <Paper
          p="md"
          radius="lg"
          withBorder
          style={{
            borderLeftWidth: 4,
            borderLeftColor: "var(--mantine-color-red-6)",
          }}
        >
          <Group gap="sm">
            <IconAlertTriangle size={28} color="var(--mantine-color-red-6)" />
            <div>
              <Text size="xs" c="dimmed" fw={700}>
                OPEN
              </Text>
              <Text size="xl" fw={800} c="red.6">
                {open}
              </Text>
              <Text size="xs" c="dimmed">
                Failing targets
              </Text>
            </div>
          </Group>
        </Paper>
        <Paper
          p="md"
          radius="lg"
          withBorder
          style={{
            borderLeftWidth: 4,
            borderLeftColor: "var(--mantine-color-yellow-6)",
          }}
        >
          <Group gap="sm">
            <IconLoader2 size={28} color="var(--mantine-color-yellow-6)" />
            <div>
              <Text size="xs" c="dimmed" fw={700}>
                HALF-OPEN
              </Text>
              <Text size="xl" fw={800} c="yellow.6">
                {halfOpen}
              </Text>
              <Text size="xs" c="dimmed">
                Testing recovery
              </Text>
            </div>
          </Group>
        </Paper>
      </SimpleGrid>

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
                <CircuitRow
                  key={r.id}
                  routeId={r.id}
                  routeName={r.name || r.id}
                  stateFilter={stateFilter}
                />
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Card>
    </Stack>
  );
}
