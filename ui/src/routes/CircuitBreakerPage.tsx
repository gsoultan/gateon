import { useState, useEffect } from "react";
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
  Pagination,
  Box,
} from "@mantine/core";
import {
  IconCircuitSwitchClosed,
  IconAlertTriangle,
  IconCircleCheck,
  IconLoader2,
  IconHistory,
} from "@tabler/icons-react";
import { useRoutes, useAggStats, useCircuitBreakerEvents } from "../hooks/useGateon";
import { useTableDensity } from "../hooks/useTableDensity";
import { CircuitRow, type CircuitState } from "../components/CircuitRow";

const PAGE_SIZE = 15;

export default function CircuitBreakerPage() {
  const density = useTableDensity();
  const [page, setPage] = useState(1);
  const { data, isLoading } = useRoutes({
    page: page - 1,
    page_size: PAGE_SIZE,
  });
  const { data: aggStats } = useAggStats();
  const { data: events } = useCircuitBreakerEvents();
  const [stateFilter, setStateFilter] = useState<CircuitState>("all");
  const [eventPage, setEventPage] = useState(1);

  // Newest events first; paginate the reversed list.
  const orderedEvents = (events ?? []).slice().reverse();
  const eventTotalPages = Math.max(1, Math.ceil(orderedEvents.length / PAGE_SIZE));
  const pagedEvents = orderedEvents.slice((eventPage - 1) * PAGE_SIZE, eventPage * PAGE_SIZE);

  useEffect(() => {
    if (eventPage > eventTotalPages) setEventPage(eventTotalPages);
  }, [orderedEvents.length, eventTotalPages, eventPage]);

  const routes = data?.routes ?? [];
  const totalCount = data?.total_count ?? 0;
  const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));
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
          <>
            <Table {...density} withRowBorders highlightOnHover>
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
            {totalCount > PAGE_SIZE && (
              <Box p="md" style={{ borderTop: "1px solid var(--mantine-color-default-border)" }}>
                <Group justify="space-between" align="center">
                  <Text size="xs" c="dimmed">
                    Showing {((page - 1) * PAGE_SIZE) + 1}–{Math.min(page * PAGE_SIZE, totalCount)} of {totalCount} routes
                  </Text>
                  <Pagination
                    total={totalPages}
                    value={page}
                    onChange={setPage}
                    size="sm"
                    radius="md"
                  />
                </Group>
              </Box>
            )}
          </>
        )}
      </Card>

      <Title order={3} fw={800} mt="xl" style={{ letterSpacing: -0.5 }}>
        <Group gap="xs">
          <IconHistory size={24} />
          Event Timeline
        </Group>
      </Title>

      <Card shadow="xs" padding="lg" radius="lg" withBorder>
        {!events || events.length === 0 ? (
          <Center py={40}>
            <Text c="dimmed">No circuit breaker events recorded yet.</Text>
          </Center>
        ) : (
          <Table {...density}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Time</Table.Th>
                <Table.Th>Target</Table.Th>
                <Table.Th>New State</Table.Th>
                <Table.Th>Reason</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {pagedEvents.map((e, i) => (
                <Table.Tr key={i}>
                  <Table.Td>
                    <Text size="xs" c="dimmed">
                      {new Date(e.timestamp).toLocaleString()}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="xs" fw={500}>{e.target}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Badge
                      size="sm"
                      color={e.state === "CLOSED" ? "green" : e.state === "OPEN" ? "red" : "yellow"}
                    >
                      {e.state}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    <Text size="xs" c="dimmed">{e.reason}</Text>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
        {orderedEvents.length > PAGE_SIZE && (
          <Group justify="space-between" align="center" mt="md">
            <Text size="xs" c="dimmed">
              Showing {((eventPage - 1) * PAGE_SIZE) + 1}–{Math.min(eventPage * PAGE_SIZE, orderedEvents.length)} of {orderedEvents.length}
            </Text>
            <Pagination total={eventTotalPages} value={eventPage} onChange={setEventPage} size="sm" radius="md" />
          </Group>
        )}
      </Card>
    </Stack>
  );
}
