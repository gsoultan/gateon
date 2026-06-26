import { memo, useState, useMemo, useEffect } from "react";
import { Table, Text, Paper, Group, Badge, Title, Pagination } from "@mantine/core";
import { formatBytes } from "../../utils/format";
import { useTableDensity } from "../../hooks/useTableDensity";

const PAGE_SIZE = 10;

interface HourlyDomainMetric {
  domain: string;
  request_count: number;
  bytes_total: number;
  avg_latency_seconds: number;
}

interface DomainStatsTableProps {
  metrics: HourlyDomainMetric[];
}

export const DomainStatsTable = memo(function DomainStatsTable({
  metrics,
}: DomainStatsTableProps) {
  const density = useTableDensity();
  const [page, setPage] = useState(1);

  const total = metrics?.length ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [total, totalPages, page]);

  const paginated = useMemo(
    () => (metrics ?? []).slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE),
    [metrics, page],
  );

  if (!metrics || metrics.length === 0) {
    return (
      <Paper p="md" radius="md" withBorder>
        <Text size="sm" c="dimmed" ta="center">
          No hourly domain data available yet.
        </Text>
      </Paper>
    );
  }

  const rows = paginated.map((m, i) => (
    <Table.Tr key={i}>
      <Table.Td>
        <Text fw={600} size="sm">
          {m.domain}
        </Text>
      </Table.Td>
      <Table.Td>
        <Badge variant="light" color="brand" size="sm">
          {m.request_count.toLocaleString()}
        </Badge>
      </Table.Td>
      <Table.Td>
        <Text size="sm" fw={500}>
          {formatBytes(m.bytes_total)}
        </Text>
      </Table.Td>
      <Table.Td>
        <Text
          size="sm"
          fw={700}
          c={
            m.avg_latency_seconds > 1
              ? "red"
              : m.avg_latency_seconds > 0.5
                ? "orange"
                : "teal"
          }
        >
          {m.avg_latency_seconds.toFixed(3)}s
        </Text>
      </Table.Td>
    </Table.Tr>
  ));

  return (
    <Paper p="lg" radius="md" withBorder shadow="xs">
      <Group justify="space-between" mb="lg">
        <div>
          <Title order={5} fw={800} style={{ letterSpacing: -0.2 }}>
            Traffic by Domain
          </Title>
          <Text size="xs" c="dimmed">
            Requests and bandwidth in the last 24 hours
          </Text>
        </div>
      </Group>

      <Table.ScrollContainer minWidth={500}>
        <Table {...density}>
          <Table.Thead>
            <Table.Tr>
              <Table.Th
                style={{
                  textTransform: "uppercase",
                  fontSize: "10px",
                  letterSpacing: "1px",
                }}
              >
                Domain
              </Table.Th>
              <Table.Th
                style={{
                  textTransform: "uppercase",
                  fontSize: "10px",
                  letterSpacing: "1px",
                }}
              >
                Requests
              </Table.Th>
              <Table.Th
                style={{
                  textTransform: "uppercase",
                  fontSize: "10px",
                  letterSpacing: "1px",
                }}
              >
                Bandwidth
              </Table.Th>
              <Table.Th
                style={{
                  textTransform: "uppercase",
                  fontSize: "10px",
                  letterSpacing: "1px",
                }}
              >
                Avg Latency
              </Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>{rows}</Table.Tbody>
        </Table>
      </Table.ScrollContainer>

      {total > PAGE_SIZE && (
        <Group justify="space-between" align="center" mt="md">
          <Text size="xs" c="dimmed">
            Showing {((page - 1) * PAGE_SIZE) + 1}–{Math.min(page * PAGE_SIZE, total)} of {total}
          </Text>
          <Pagination total={totalPages} value={page} onChange={setPage} size="sm" radius="md" />
        </Group>
      )}
    </Paper>
  );
});
