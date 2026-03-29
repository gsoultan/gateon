import {
  Title,
  Text,
  Card,
  Table,
  Badge,
  Group,
  Stack,
  ActionIcon,
  Tooltip,
  Paper,
  Box,
  Divider,
  ScrollArea,
  Code,
  TextInput,
  Button,
} from "@mantine/core";
import {
  IconSearch,
  IconRefresh,
  IconExternalLink,
  IconTimeline,
  IconCircleCheck,
  IconCircleX,
} from "@tabler/icons-react";
import { useState } from "react";

import { useTraces } from "../hooks/useGateon";

export default function TracesPage() {
  const { data: traces = [], isLoading, refetch } = useTraces();

  return (
    <Stack gap="lg">
      <Group justify="space-between">
        <Stack gap={0}>
          <Title order={2}>Distributed Tracing</Title>
          <Text c="dimmed">
            Monitor and visualize end-to-end request flows across your
            microservices.
          </Text>
        </Stack>
        <Group>
          <Button 
            leftSection={<IconRefresh size={16} />} 
            variant="light"
            loading={isLoading}
            onClick={() => refetch()}
          >
            Refresh
          </Button>
          <Tooltip label="Open in Jaeger">
            <ActionIcon variant="light" color="blue" size="lg">
              <IconExternalLink size={20} />
            </ActionIcon>
          </Tooltip>
        </Group>
      </Group>

      <Card withBorder padding="md">
        <Stack gap="md">
          <Group justify="space-between">
            <TextInput
              placeholder="Search traces by ID, service, or path..."
              leftSection={<IconSearch size={16} />}
              style={{ flex: 1 }}
            />
          </Group>

          <ScrollArea>
            <Table highlightOnHover verticalSpacing="sm">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>ID</Table.Th>
                  <Table.Th>Operation</Table.Th>
                  <Table.Th>Service</Table.Th>
                  <Table.Th>Path</Table.Th>
                  <Table.Th>Duration</Table.Th>
                  <Table.Th>Status</Table.Th>
                  <Table.Th>Timestamp</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {traces.map((trace) => (
                  <Table.Tr key={trace.id}>
                    <Table.Td>
                      <Code color="blue.1" c="blue.8">
                        {trace.id}
                      </Code>
                    </Table.Td>
                    <Table.Td>
                      <Text fw={500}>{trace.operation_name}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Badge variant="light">{trace.service_name}</Badge>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" c="dimmed">
                        {trace.path}
                      </Text>
                    </Table.Td>
                    <Table.Td>{trace.duration_ms}ms</Table.Td>
                    <Table.Td>
                      {trace.status === "success" ? (
                        <IconCircleCheck color="green" size={20} />
                      ) : (
                        <IconCircleX color="red" size={20} />
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Text size="xs">{new Date(trace.timestamp).toLocaleString()}</Text>
                    </Table.Td>
                  </Table.Tr>
                ))}
                {traces.length === 0 && !isLoading && (
                  <Table.Tr>
                    <Table.Td colSpan={7} style={{ textAlign: "center" }}>
                      <Text c="dimmed">No traces found.</Text>
                    </Table.Td>
                  </Table.Tr>
                )}
              </Table.Tbody>
            </Table>
          </ScrollArea>
        </Stack>
      </Card>

      <Paper withBorder p="xl" radius="md">
        <Stack align="center" gap="sm">
          <IconTimeline size={48} stroke={1.5} color="var(--mantine-color-blue-6)" />
          <Title order={3}>Live Trace Visualization</Title>
          <Text c="dimmed" ta="center" style={{ maxWidth: 500 }}>
            Gateon is currently exporting telemetry via OpenTelemetry Protocol (OTLP). 
            For full visualization of spans and child relationships, we recommend 
            integrating with a dedicated store like Jaeger or Honeycomb.
          </Text>
          <Box mt="md">
             <Divider label="Visualization Preview" labelPosition="center" mb="xl" />
             <Stack gap="xs" style={{ minWidth: 600 }}>
                <Paper withBorder p="xs" style={{ backgroundColor: "rgba(0,0,0,0.02)" }}>
                   <Group gap="xs">
                      <Badge size="xs" color="blue">GATEWAY</Badge>
                      <div style={{ flex: 1, height: 8, backgroundColor: "#339af0", borderRadius: 4 }} />
                      <Text size="xs">42ms</Text>
                   </Group>
                </Paper>
                <Paper withBorder p="xs" ml={40} style={{ backgroundColor: "rgba(0,0,0,0.02)" }}>
                   <Group gap="xs">
                      <Badge size="xs" color="violet">AUTH-MW</Badge>
                      <div style={{ flex: 0.2, height: 8, backgroundColor: "#7950f2", borderRadius: 4 }} />
                      <Text size="xs">8ms</Text>
                   </Group>
                </Paper>
                <Paper withBorder p="xs" ml={80} style={{ backgroundColor: "rgba(0,0,0,0.02)" }}>
                   <Group gap="xs">
                      <Badge size="xs" color="teal">USER-SVC</Badge>
                      <div style={{ flex: 0.6, height: 8, backgroundColor: "#0ca678", borderRadius: 4 }} />
                      <Text size="xs">25ms</Text>
                   </Group>
                </Paper>
             </Stack>
          </Box>
        </Stack>
      </Paper>
    </Stack>
  );
}
