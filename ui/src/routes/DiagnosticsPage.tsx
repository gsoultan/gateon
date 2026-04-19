import React, { useEffect, useState } from "react";
import {
  Card,
  Group,
  Stack,
  Text,
  Title,
  Badge,
  ActionIcon,
  SimpleGrid,
  Table,
  Alert,
  LoadingOverlay,
  ScrollArea,
  Paper,
  Tooltip,
  Divider,
  Anchor,
  Box,
  useMantineTheme,
} from "@mantine/core";
import { getDiagnostics } from "../hooks/api";
import type { GetDiagnosticsResponse } from "../types/gateon";
import {
  IconActivity,
  IconAlertTriangle,
  IconCircleCheck,
  IconGlobe,
  IconShield,
  IconServer,
  IconRefresh,
  IconClock,
  IconExternalLink,
  IconAccessPoint,
  IconInfoCircle,
} from "@tabler/icons-react";

const DiagnosticsPage: React.FC = () => {
  const [data, setData] = useState<GetDiagnosticsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const theme = useMantineTheme();

  const fetchData = async () => {
    try {
      setLoading(true);
      const res = await getDiagnostics();
      setData(res);
      setError(null);
    } catch (err: any) {
      setError(err.message || "Failed to fetch diagnostics");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000); // Refresh every 10s
    return () => clearInterval(interval);
  }, []);

  if (error && !data) {
    return (
      <Stack gap="md" p="xl" align="center">
        <Alert
          variant="light"
          color="red"
          title="Error"
          icon={<IconAlertTriangle size={20} />}
          style={{ maxWidth: 500 }}
        >
          {error}
        </Alert>
        <ActionIcon variant="light" size="xl" onClick={fetchData} loading={loading}>
          <IconRefresh size={24} />
        </ActionIcon>
        <Text c="dimmed" size="sm">Retry fetching diagnostics</Text>
      </Stack>
    );
  }

  return (
    <Box pos="relative" style={{ transition: "all 0.3s ease" }}>
      <LoadingOverlay visible={loading && !data} overlayProps={{ blur: 2 }} />

      <Stack gap="xl">
        <Group justify="space-between" align="flex-end">
          <Stack gap={4}>
            <Title order={2} fw={800} style={{ letterSpacing: -0.5 }}>
              Diagnostics & Connectivity
            </Title>
            <Text c="dimmed" size="sm" fw={500}>
              Monitor real-time system health, TLS status, and entrypoint performance.
            </Text>
          </Stack>
          <ActionIcon
            variant="default"
            size="lg"
            radius="md"
            onClick={fetchData}
            loading={loading}
          >
            <IconRefresh size={18} />
          </ActionIcon>
        </Group>

        {/* System Status Summary */}
        <SimpleGrid cols={{ base: 1, md: 3 }} spacing="md">
          <Paper withBorder p="lg" radius="lg" shadow="xs">
            <Group justify="space-between" mb="xs">
              <Text size="xs" c="dimmed" fw={800} style={{ textTransform: "uppercase", letterSpacing: 1 }}>
                Public IP Address
              </Text>
              <IconGlobe size={20} color={theme.colors.blue[6]} />
            </Group>
            <Title order={3} fw={900} ff="monospace">
              {data?.system.public_ip || "Unknown"}
            </Title>
            <Text size="xs" c="dimmed" mt="xs">
              Ensure DNS records point to this IP.
            </Text>
          </Paper>

          <Paper withBorder p="lg" radius="lg" shadow="xs">
            <Group justify="space-between" mb="xs">
              <Text size="xs" c="dimmed" fw={800} style={{ textTransform: "uppercase", letterSpacing: 1 }}>
                Cloudflare Reachability
              </Text>
              <IconShield size={20} color={theme.colors.orange[6]} />
            </Group>
            <Group gap="xs">
              {data?.system.cloudflare_reachable ? (
                <>
                  <IconCircleCheck size={24} color={theme.colors.emerald[6]} />
                  <Title order={3} fw={900}>Reachable</Title>
                </>
              ) : (
                <>
                  <IconAlertTriangle size={24} color={theme.colors.red[6]} />
                  <Title order={3} fw={900}>Unreachable</Title>
                </>
              )}
            </Group>
            <Text size="xs" c="dimmed" mt="xs">
              TCP check to 1.1.1.1:53.
            </Text>
          </Paper>

          <Paper withBorder p="lg" radius="lg" shadow="xs">
            <Group justify="space-between" mb="xs">
              <Text size="xs" c="dimmed" fw={800} style={{ textTransform: "uppercase", letterSpacing: 1 }}>
                Recent TLS Errors
              </Text>
              <IconActivity size={20} color={theme.colors.violet[6]} />
            </Group>
            <Title order={3} fw={900}>
              {data?.recent_tls_errors.length || 0}
            </Title>
            <Text size="xs" c="dimmed" mt="xs">
              Handshake failures in the last buffer.
            </Text>
          </Paper>
        </SimpleGrid>

        {/* Troubleshooting Tips */}
        <Alert
          variant="light"
          color="blue"
          title="Cloudflare 521 Troubleshooting"
          icon={<IconInfoCircle size={20} />}
          radius="lg"
        >
          <Stack gap={4}>
            <Text size="sm">
              If Cloudflare shows 521 (Web Server Is Down):
            </Text>
            <Box component="ul" style={{ paddingLeft: 20, margin: 0 }}>
              <Text component="li" size="xs">Verify firewall allows <Anchor href="https://www.cloudflare.com/ips/" target="_blank" size="xs">Cloudflare IP ranges</Anchor>.</Text>
              <Text component="li" size="xs">Ensure Gateon is listening on the expected port (usually 443).</Text>
              <Text component="li" size="xs">"Full (strict)" mode requires a valid certificate on Gateon.</Text>
              <Text component="li" size="xs">Check the "Recent TLS Errors" below for handshake issues.</Text>
            </Box>
          </Stack>
        </Alert>

        <SimpleGrid cols={{ base: 1, lg: 2 }} spacing="xl">
          {/* Entrypoints List */}
          <Card withBorder radius="lg" shadow="sm" p={0}>
            <Group p="md" bg="var(--mantine-color-default-hover)" justify="space-between">
              <Group gap="xs">
                <IconAccessPoint size={20} c="dimmed" />
                <Title order={4} fw={800}>Entrypoint Status</Title>
              </Group>
              <Badge variant="dot" color="blue" size="sm">Live</Badge>
            </Group>
            <Divider />
            <ScrollArea>
              <Table verticalSpacing="sm" horizontalSpacing="md" highlightOnHover>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Name / ID</Table.Th>
                    <Table.Th>Address</Table.Th>
                    <Table.Th>Connections</Table.Th>
                    <Table.Th>Status</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {data?.entrypoints.map((ep) => (
                    <Table.Tr key={ep.id}>
                      <Table.Td>
                        <Stack gap={0}>
                          <Text size="sm" fw={700}>{ep.name || "Unnamed"}</Text>
                          <Text size="xs" c="dimmed" ff="monospace">{ep.id}</Text>
                        </Stack>
                      </Table.Td>
                      <Table.Td>
                        <Text size="sm" ff="monospace" c="dimmed">{ep.address}</Text>
                      </Table.Td>
                      <Table.Td>
                        <Group gap={4}>
                          <Text size="sm" fw={800} c="blue">{ep.active_connections}</Text>
                          <Text size="xs" c="dimmed">/</Text>
                          <Text size="xs" c="dimmed">{ep.total_connections}</Text>
                        </Group>
                      </Table.Td>
                      <Table.Td>
                        <Stack gap={4}>
                          <Badge
                            variant="light"
                            color={ep.listening ? "green" : "red"}
                            size="xs"
                            radius="sm"
                          >
                            {ep.listening ? "Listening" : "Stopped"}
                          </Badge>
                          {ep.last_error && (
                            <Tooltip label={ep.last_error}>
                              <Text size="10px" c="red" truncate maw={120}>
                                {ep.last_error}
                              </Text>
                            </Tooltip>
                          )}
                        </Stack>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                  {(!data?.entrypoints || data.entrypoints.length === 0) && (
                    <Table.Tr>
                      <Table.Td colSpan={4}>
                        <Text c="dimmed" ta="center" py="xl" size="sm">No entrypoints configured.</Text>
                      </Table.Td>
                    </Table.Tr>
                  )}
                </Table.Tbody>
              </Table>
            </ScrollArea>
          </Card>

          {/* Recent TLS Errors */}
          <Card withBorder radius="lg" shadow="sm" p={0}>
            <Group p="md" bg="var(--mantine-color-default-hover)" justify="space-between">
              <Group gap="xs">
                <IconShield size={20} c="dimmed" />
                <Title order={4} fw={800}>Recent TLS Handshake Errors</Title>
              </Group>
              <Badge variant="filled" color="red" size="sm">{data?.recent_tls_errors.length || 0}</Badge>
            </Group>
            <Divider />
            <ScrollArea h={400}>
              {data?.recent_tls_errors.length === 0 ? (
                <Stack align="center" justify="center" h="100%" py="xl" gap="xs">
                  <IconCircleCheck size={48} color={theme.colors.emerald[2]} />
                  <Text c="dimmed" size="sm" fw={500}>No recent TLS errors detected.</Text>
                </Stack>
              ) : (
                <Stack gap={0} p={0}>
                  {data?.recent_tls_errors.map((err, i) => (
                    <Paper key={i} p="md" radius={0} className="hover:bg-mantine-color-default-hover" style={{ borderBottom: "1px solid var(--mantine-color-gray-2)" }}>
                      <Group justify="space-between" mb={4}>
                        <Group gap={6}>
                          <IconClock size={12} color={theme.colors.gray[5]} />
                          <Text size="xs" c="dimmed" fw={700} ff="monospace">
                            {new Date(err.timestamp).toLocaleTimeString()}
                          </Text>
                        </Group>
                        <Tooltip label={`ID: ${err.entrypoint_id}`}>
                          <Badge variant="outline" color="gray" size="xs">
                            {err.entrypoint_name || err.entrypoint_id}
                          </Badge>
                        </Tooltip>
                      </Group>
                      <Text size="sm" ff="monospace" fw={500} mb={8} style={{ wordBreak: "break-all" }}>
                        {err.remote_addr}
                      </Text>
                      <Alert variant="light" color="red" p="xs" radius="md">
                        <Text size="xs" ff="monospace" fw={600}>{err.error}</Text>
                      </Alert>
                    </Paper>
                  ))}
                </Stack>
              )}
            </ScrollArea>
          </Card>
        </SimpleGrid>
      </Stack>
    </Box>
  );
};

export default DiagnosticsPage;
