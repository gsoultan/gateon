import { useState, useMemo, useTransition, useEffect } from "react";
import { usePathStats } from "../hooks/useGateon";
import {
  Table,
  Card,
  Text,
  Group,
  Stack,
  Title,
  Badge,
  Skeleton,
  Box,
  TextInput,
  Pagination,
} from "@mantine/core";
import { IconActivity, IconSearch } from "@tabler/icons-react";

const PAGE_SIZE = 15;

export function PathStatsTable() {
  const { data, isLoading } = usePathStats();
  const [hostFilter, setHostFilter] = useState("");
  const [deferredFilter, setDeferredFilter] = useState("");
  const [page, setPage] = useState(1);
  const [isPending, startTransition] = useTransition();

  const filteredData = useMemo(() => {
    if (!data) return [];
    if (!deferredFilter) return data;
    const lowerFilter = deferredFilter.toLowerCase();
    return data.filter((stat) =>
      stat.host.toLowerCase().includes(lowerFilter) ||
      stat.path.toLowerCase().includes(lowerFilter)
    );
  }, [data, deferredFilter]);

  const paginatedData = useMemo(() => {
    const start = (page - 1) * PAGE_SIZE;
    return filteredData.slice(start, start + PAGE_SIZE);
  }, [filteredData, page]);

  const totalPages = Math.max(1, Math.ceil(filteredData.length / PAGE_SIZE));

  useEffect(() => {
    if (page > totalPages && totalPages > 0) setPage(totalPages);
  }, [filteredData.length, totalPages, page]);

  const handleFilterChange = (val: string) => {
    setHostFilter(val);
    setPage(1);
    startTransition(() => {
      setDeferredFilter(val);
    });
  };

  if (isLoading) {
    return <Skeleton h={200} />;
  }

  if (!data || data.length === 0) {
    return (
      <Card withBorder padding="xl" radius="md">
        <Text c="dimmed" ta="center">
          No path metrics collected yet.
        </Text>
      </Card>
    );
  }

  return (
    <Card shadow="xs" padding="lg" radius="lg" withBorder>
      <Stack gap="md">
        <Group justify="space-between">
          <Group gap="xs">
            <IconActivity size={20} color="var(--mantine-color-blue-filled)" />
            <Title order={4} fw={700}>
              Path Metrics
            </Title>
            <Badge variant="light" color="blue" size="sm" radius="md">
              {filteredData.length} paths
            </Badge>
          </Group>
          <TextInput
            placeholder="Filter by host or path..."
            leftSection={<IconSearch size={16} />}
            value={hostFilter}
            onChange={(e) => handleFilterChange(e.currentTarget.value)}
            size="xs"
            w={250}
            rightSection={isPending ? <Text size="xs">...</Text> : null}
          />
        </Group>

        <Box style={{ overflowX: "auto" }}>
          <Table verticalSpacing="sm" horizontalSpacing="md" withRowBorders>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Host</Table.Th>
                <Table.Th>Path</Table.Th>
                <Table.Th ta="right">Requests</Table.Th>
                <Table.Th ta="right">Avg Latency (s)</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody style={{ opacity: isPending ? 0.7 : 1, transition: 'opacity 0.2s' }}>
              {paginatedData.map((stat) => (
                <Table.Tr key={`${stat.host}${stat.path}`}>
                  <Table.Td>
                    <Text size="sm" fw={500}>
                      {stat.host}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" c="dimmed" style={{ fontFamily: "monospace" }}>
                      {stat.path}
                    </Text>
                  </Table.Td>
                  <Table.Td ta="right">
                    <Badge variant="flat" color="gray">
                      {stat.request_count.toLocaleString()}
                    </Badge>
                  </Table.Td>
                  <Table.Td ta="right">
                    <Text
                      size="sm"
                      fw={600}
                      c={stat.avg_latency_seconds > 0.5 ? "orange" : "green"}
                    >
                      {stat.avg_latency_seconds.toFixed(3)}s
                    </Text>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
          {filteredData.length === 0 && !isPending && (
            <Text c="dimmed" ta="center" py="xl">
              No matching paths found.
            </Text>
          )}
        </Box>
        {filteredData.length > PAGE_SIZE && (
          <Group justify="space-between" align="center" pt="md" style={{ borderTop: "1px solid var(--mantine-color-default-border)" }}>
            <Text size="xs" c="dimmed">
              Showing {((page - 1) * PAGE_SIZE) + 1}–{Math.min(page * PAGE_SIZE, filteredData.length)} of {filteredData.length}
            </Text>
            <Pagination total={totalPages} value={page} onChange={setPage} size="sm" radius="md" />
          </Group>
        )}
      </Stack>
    </Card>
  );
}
