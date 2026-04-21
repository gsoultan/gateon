import { Table, Text, Paper, Group, Box, Progress } from "@mantine/core";
import { getCountryFlag, formatBytes } from "../../utils/format";

interface CountryMetric {
  group: string;
  name?: string;
  requests: number;
}

interface CountryTrafficTableProps {
  title: string;
  subtitle: string;
  data: CountryMetric[];
  totalRequests: number;
  isBandwidth?: boolean;
}

export function CountryTrafficTable({ 
  title, 
  subtitle, 
  data, 
  totalRequests,
  isBandwidth = false
}: CountryTrafficTableProps) {
  if (!data || data.length === 0) {
    return (
      <Paper p="md" radius="md" withBorder>
        <Text size="sm" fw={700}>{title}</Text>
        <Text size="xs" c="dimmed" mb="sm">{subtitle}</Text>
        <Text size="sm" c="dimmed" ta="center" py="xl">No data available.</Text>
      </Paper>
    );
  }

  const rows = data.map((m) => {
    const percentage = totalRequests > 0 ? (m.requests / totalRequests) * 100 : 0;
    return (
      <Table.Tr key={m.group}>
        <Table.Td>
          <Group gap="xs">
            <Text size="lg">{getCountryFlag(m.group)}</Text>
            <Box>
              <Text size="sm" fw={500}>{m.name || m.group}</Text>
              {m.name && <Text size="xs" c="dimmed" style={{ lineHeight: 1 }}>{m.group}</Text>}
            </Box>
          </Group>
        </Table.Td>
        <Table.Td>
          <Box style={{ width: "100%" }}>
            <Group justify="space-between" mb={2}>
              <Text size="xs" fw={700}>
                {isBandwidth ? formatBytes(m.requests) : `${m.requests.toLocaleString()} req`}
              </Text>
              <Text size="xs" c="dimmed">{percentage.toFixed(1)}%</Text>
            </Group>
            <Progress value={percentage} size="xs" radius="xl" color="blue" />
          </Box>
        </Table.Td>
      </Table.Tr>
    );
  });

  return (
    <Paper p="md" radius="md" withBorder>
      <Text size="sm" fw={700}>{title}</Text>
      <Text size="xs" c="dimmed" mb="md">{subtitle}</Text>
      <Table verticalSpacing="xs">
        <Table.Tbody>{rows}</Table.Tbody>
      </Table>
    </Paper>
  );
}
