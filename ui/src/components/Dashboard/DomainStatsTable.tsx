import { Table, Text, Paper, Box, Group, Badge } from "@mantine/core";
import { formatBytes } from "../../utils/format";

interface HourlyDomainMetric {
  domain: string;
  request_count: number;
  bytes_total: number;
  avg_latency_seconds: number;
}

interface DomainStatsTableProps {
  metrics: HourlyDomainMetric[];
}

export function DomainStatsTable({ metrics }: DomainStatsTableProps) {
  if (!metrics || metrics.length === 0) {
    return (
      <Paper p="md" radius="md" withBorder>
        <Text size="sm" c="dimmed" ta="center">
          No hourly domain data available yet.
        </Text>
      </Paper>
    );
  }

  const rows = metrics.map((m, i) => (
    <Table.Tr key={i}>
      <Table.Td>
        <Text fw={500} size="sm">
          {m.domain}
        </Text>
      </Table.Td>
      <Table.Td>
        <Badge variant="light" color="blue">
          {m.request_count.toLocaleString()}
        </Badge>
      </Table.Td>
      <Table.Td>
        <Text size="sm">{formatBytes(m.bytes_total)}</Text>
      </Table.Td>
      <Table.Td>
        <Text size="sm" color={m.avg_latency_seconds > 1 ? "red" : m.avg_latency_seconds > 0.5 ? "orange" : "teal"}>
          {m.avg_latency_seconds.toFixed(3)}s
        </Text>
      </Table.Td>
    </Table.Tr>
  ));

  return (
    <Paper p="md" radius="md" withBorder>
      <Group justify="space-between" mb="md">
        <div>
          <Text size="sm" fw={700}>
            Current Hour Traffic by Domain
          </Text>
          <Text size="xs" c="dimmed">
            Requests and bandwidth in the current hour (UTC)
          </Text>
        </div>
      </Group>

      <Table.ScrollContainer minWidth={500}>
        <Table verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Domain</Table.Th>
              <Table.Th>Requests</Table.Th>
              <Table.Th>Bandwidth</Table.Th>
              <Table.Th>Avg Latency</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>{rows}</Table.Tbody>
        </Table>
      </Table.ScrollContainer>
    </Paper>
  );
}
