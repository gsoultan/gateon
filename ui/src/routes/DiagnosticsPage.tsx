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
  Alert,
  LoadingOverlay,
  ScrollArea,
  Paper,
  Tooltip,
  Divider,
  Anchor,
  Box,
  useMantineTheme,
  Accordion,
  ThemeIcon,
} from "@mantine/core";
import { getDiagnostics, applyRecommendation } from "../hooks/api";
import type { GetDiagnosticsResponse, RouteDiagnostic, MiddlewareDiagnostic, Anomaly, DependencyHealth } from "../types/gateon";
import {
  IconActivity,
  IconAlertTriangle,
  IconCircleCheck,
  IconGlobe,
  IconShield,
  IconServer,
  IconRefresh,
  IconClock,
  IconAccessPoint,
  IconInfoCircle,
  IconRoute,
  IconArrowRight,
  IconCheck,
  IconX,
  IconRobot,
  IconBug,
  IconLock,
  IconShieldLock,
} from "@tabler/icons-react";
import { notifications } from "@mantine/notifications";

const MiddlewareBadge: React.FC<{ mw: MiddlewareDiagnostic }> = ({ mw }) => (
  <Tooltip label={mw.error || `Type: ${mw.type}`}>
    <Badge
      variant="light"
      color={mw.healthy ? "blue" : "red"}
      leftSection={mw.healthy ? <IconCheck size={10} /> : <IconX size={10} />}
      size="sm"
      style={{ textTransform: "none" }}
    >
      {mw.name || mw.id}
    </Badge>
  </Tooltip>
);

const SystemStatCard: React.FC<{ title: string; value: string | number; icon: React.ReactNode }> = ({ title, value, icon }) => (
  <Paper withBorder p="md" radius="lg" shadow="xs">
    <Group justify="space-between" mb="xs">
      <Text size="xs" c="dimmed" fw={800} style={{ textTransform: "uppercase", letterSpacing: 1 }}>
        {title}
      </Text>
      {icon}
    </Group>
    <Title order={3} fw={900}>
      {value || "---"}
    </Title>
  </Paper>
);

const DependencyBadge: React.FC<{ dep: DependencyHealth }> = ({ dep }) => (
  <Paper withBorder p="sm" radius="md" bg="var(--mantine-color-gray-0)">
    <Group justify="space-between">
      <Text size="sm" fw={700}>{dep.name}</Text>
      <Badge color={dep.healthy ? "teal" : "red"} variant="dot">
        {dep.healthy ? "Healthy" : "Degraded"}
      </Badge>
    </Group>
    <Group justify="space-between" mt={4}>
      <Text size="xs" c="dimmed">Latency: {dep.latency_ms}</Text>
      {dep.error && <Text size="xs" c="red" fw={500} truncate maw={200}>{dep.error}</Text>}
    </Group>
  </Paper>
);

const RouteTrace: React.FC<{ route: RouteDiagnostic }> = ({ route }) => {
  return (
    <Paper withBorder p="md" radius="md" mb="sm" shadow="xs">
      <Stack gap="xs">
        <Group justify="space-between">
          <Group gap="xs">
            <ThemeIcon color={route.healthy ? "teal" : "red"} variant="light" size="md" radius="md">
              <IconRoute size={18} />
            </ThemeIcon>
            <Stack gap={0}>
              <Text fw={700} size="sm">{route.name || "Unnamed Route"}</Text>
              <Text size="xs" c="dimmed" ff="monospace">{route.id}</Text>
            </Stack>
          </Group>
          <Group gap="xs">
            {route.healthy ? (
              <Badge color="teal" variant="light" size="sm">Healthy Path</Badge>
            ) : (
              <Badge color="red" variant="filled" size="sm">Path Broken</Badge>
            )}
          </Group>
        </Group>

        <Paper p="xs" radius="xs" withBorder style={{ borderStyle: "dashed", backgroundColor: "var(--mantine-color-gray-0)" }}>
          <Text size="xs" c="dimmed" ff="monospace">
            Rule: {route.rule}
          </Text>
        </Paper>

        <Group gap="sm" wrap="nowrap" mt="xs" justify="center" style={{ overflowX: "auto", paddingBottom: 8 }}>
          <Stack align="center" gap={4} style={{ minWidth: 80 }}>
            <ThemeIcon radius="xl" size="md" color="blue" variant="light">
              <IconAccessPoint size={18}/>
            </ThemeIcon>
            <Text size="10px" fw={700}>Entrypoint</Text>
          </Stack>

          <IconArrowRight size={16} color="gray" />

          <Stack align="center" gap={4} style={{ minWidth: 120 }}>
            <Group gap={4} justify="center">
              {route.middlewares && route.middlewares.length > 0 ? (
                route.middlewares.map(mw => (
                  <MiddlewareBadge key={mw.id} mw={mw} />
                ))
              ) : (
                <Badge variant="transparent" color="gray" size="sm">No Middleware</Badge>
              )}
            </Group>
            <Text size="10px" fw={700}>Middlewares</Text>
          </Stack>

          <IconArrowRight size={16} color="gray" />

          <Stack align="center" gap={4} style={{ minWidth: 100 }}>
             <ThemeIcon color={route.service_healthy ? "teal" : "red"} variant="filled" radius="md" size="md">
               <IconServer size={18} />
             </ThemeIcon>
             <Text size="10px" fw={700} ta="center" truncate maw={120}>
               {route.service_name || route.service_id}
             </Text>
          </Stack>
        </Group>

        {route.error && (
          <Alert color="red" variant="light" p="xs" icon={<IconAlertTriangle size={16} />}>
            <Text size="xs" fw={600}>{route.error}</Text>
          </Alert>
        )}
      </Stack>
    </Paper>
  );
};

const AnomalyCard: React.FC<{ anomaly: Anomaly; onApply: () => void; applying: boolean }> = ({ anomaly, onApply, applying }) => {
  const getSeverityColor = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical": return "red";
      case "high": return "orange";
      case "medium": return "yellow";
      default: return "blue";
    }
  };

  const getIcon = (type: string) => {
    if (type.includes("attack") || type.includes("hacker") || type.includes("violation")) return <IconShieldLock size={20} />;
    if (type.includes("brute")) return <IconLock size={20} />;
    if (type.includes("scan") || type.includes("security")) return <IconBug size={20} />;
    return <IconActivity size={20} />;
  };

  return (
    <Paper withBorder p="md" radius="lg" shadow="sm" style={{ borderLeft: `4px solid var(--mantine-color-${getSeverityColor(anomaly.severity)}-6)` }}>
      <Stack gap="xs">
        <Group justify="space-between">
          <Group gap="sm">
            <ThemeIcon variant="light" color={getSeverityColor(anomaly.severity)} size="lg" radius="md">
              {getIcon(anomaly.type)}
            </ThemeIcon>
            <Stack gap={0}>
              <Text fw={800} size="sm" style={{ textTransform: "uppercase", letterSpacing: 0.5 }}>
                {anomaly.type.replace(/_/g, " ")}
              </Text>
              <Text size="xs" c="dimmed">{new Date(anomaly.timestamp).toLocaleString()}</Text>
            </Stack>
          </Group>
          <Badge color={getSeverityColor(anomaly.severity)} variant="filled" size="xs">
            {anomaly.severity}
          </Badge>
        </Group>

        <Text size="sm" fw={500}>{anomaly.description}</Text>

        <Alert variant="light" color="indigo" radius="md" p="sm" icon={<IconRobot size={18} />}>
          <Stack gap="xs">
            <Text size="xs" fw={700}>System Recommendation:</Text>
            <Text size="xs">{anomaly.recommendation}</Text>
            <Group justify="flex-end">
              <Anchor
                component="button"
                size="xs"
                fw={800}
                onClick={onApply}
                loading={applying}
                style={{ display: "flex", alignItems: "center", gap: 4 }}
              >
                Apply Automatic Fix <IconArrowRight size={12} />
              </Anchor>
            </Group>
          </Stack>
        </Alert>
      </Stack>
    </Paper>
  );
};

const DiagnosticsPage: React.FC = () => {
  const [data, setData] = useState<GetDiagnosticsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [applying, setApplying] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const theme = useMantineTheme();

  const fetchData = async () => {
    try {
      if (!applying) { // Don't refresh while applying a fix to avoid UI jumps
        const res = await getDiagnostics();
        setData(res);
        setError(null);
      }
    } catch (err: any) {
      setError(err.message || "Failed to fetch diagnostics");
    } finally {
      setLoading(false);
    }
  };

  const handleApplyRecommendation = async (anomaly: Anomaly) => {
    const key = `${anomaly.type}-${anomaly.source}`;
    try {
      setApplying(key);
      const res = await applyRecommendation(anomaly.type, anomaly.source);
      if (res.success) {
        notifications.show({
          title: "Recommendation Applied",
          message: res.message,
          color: "teal",
          icon: <IconCheck size={18} />,
        });
        // Refresh data after a short delay
        setTimeout(fetchData, 1000);
      } else {
        notifications.show({
          title: "Fix Failed",
          message: res.message,
          color: "red",
          icon: <IconX size={18} />,
        });
      }
    } catch (err: any) {
      notifications.show({
        title: "Error",
        message: err.message || "Failed to apply recommendation",
        color: "red",
      });
    } finally {
      setApplying(null);
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

        {/* System Health Dashboard */}
        <Stack gap="sm">
          <Group gap="xs">
            <IconActivity size={20} color={theme.colors.blue[6]} />
            <Text fw={800} size="sm" style={{ textTransform: "uppercase", letterSpacing: 1 }}>System Health Dashboard</Text>
          </Group>
          <SimpleGrid cols={{ base: 1, sm: 2, md: 4, lg: 6 }} spacing="md">
            <SystemStatCard title="Public IP" value={data?.system?.public_ip} icon={<IconGlobe size={20} color="blue" />} />
            <SystemStatCard title="CPU Usage" value={data?.system?.cpu_usage} icon={<IconActivity size={20} color="red" />} />
            <SystemStatCard title="Memory" value={data?.system?.memory_usage} icon={<IconServer size={20} color="orange" />} />
            <SystemStatCard title="Goroutines" value={data?.system?.goroutines} icon={<IconRoute size={20} color="teal" />} />
            <SystemStatCard title="Uptime" value={data?.system?.uptime} icon={<IconClock size={20} color="violet" />} />
            <SystemStatCard title="Version" value={data?.system?.version} icon={<IconInfoCircle size={20} color="gray" />} />
          </SimpleGrid>
        </Stack>

        {/* Dependency Health */}
        <Card withBorder radius="lg" shadow="sm" p="lg">
          <Stack gap="md">
             <Group justify="space-between">
                <Group gap="xs">
                   <IconServer size={24} color={theme.colors.teal[6]} />
                   <Title order={3} fw={900}>Infrastructure Dependencies</Title>
                </Group>
                <Badge variant="light" color="teal">All checks active</Badge>
             </Group>
             <SimpleGrid cols={{ base: 1, md: 3 }} spacing="md">
                {data?.dependencies?.map((dep, i) => (
                   <DependencyBadge key={i} dep={dep} />
                ))}
             </SimpleGrid>
          </Stack>
        </Card>

        {/* Anomaly Detection Engine */}
        <Card withBorder radius="lg" shadow="sm" p="lg">
          <Stack gap="md">
            <Group justify="space-between">
              <Group gap="xs">
                <IconRobot size={24} color={theme.colors.indigo[6]} />
                <Title order={3} fw={900}>Anomaly Intelligence Engine</Title>
              </Group>
              <Badge variant="dot" color="indigo" size="lg">Autonomous Protection</Badge>
            </Group>
            
            <Text size="sm" c="dimmed">
              Real-time heuristic analysis of traffic patterns and security events. 
              The engine identifies potential threats and provides actionable recommendations.
            </Text>

            {data?.anomalies && data.anomalies.length > 0 ? (
              <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
                {data.anomalies.map((a, i) => (
                  <AnomalyCard 
                    key={i} 
                    anomaly={a} 
                    onApply={() => handleApplyRecommendation(a)}
                    applying={applying === `${a.type}-${a.source}`}
                  />
                ))}
              </SimpleGrid>
            ) : (
              <Paper p="xl" withBorder radius="lg" style={{ borderStyle: "dashed" }} bg="var(--mantine-color-gray-0)">
                <Stack align="center" gap="xs">
                  <IconCircleCheck size={40} color={theme.colors.teal[3]} />
                  <Text fw={700} c="teal">No Anomalies Detected</Text>
                  <Text size="xs" c="dimmed">The engine is monitoring your traffic and everything looks normal.</Text>
                </Stack>
              </Paper>
            )}
          </Stack>
        </Card>

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
          {/* Connectivity & Entrypoints */}
          <Card withBorder radius="lg" shadow="sm" p={0}>
            <Group p="md" bg="var(--mantine-color-default-hover)" justify="space-between">
              <Group gap="xs">
                <IconAccessPoint size={20} color="gray" />
                <Title order={4} fw={800}>Connectivity Trace</Title>
              </Group>
              <Badge variant="dot" color="blue" size="sm">Real-time</Badge>
            </Group>
            <Divider />
            <ScrollArea h={400}>
              <Accordion variant="separated" p="md">
                {data?.entrypoints?.map((ep) => (
                  <Accordion.Item key={ep.id} value={ep.id} style={{ border: "1px solid var(--mantine-color-gray-2)", borderRadius: "var(--mantine-radius-md)", marginBottom: 8 }}>
                    <Accordion.Control>
                      <Group justify="space-between" wrap="nowrap">
                        <Group gap="xs">
                          <ThemeIcon color={ep.listening ? "teal" : "red"} variant="light" radius="xl">
                            <IconAccessPoint size={18} />
                          </ThemeIcon>
                          <Stack gap={0}>
                            <Text size="sm" fw={700}>{ep.name || "Unnamed"}</Text>
                            <Text size="xs" c="dimmed" ff="monospace">{ep.address}</Text>
                          </Stack>
                        </Group>
                        <Group gap="xs" visibleFrom="xs">
                           <Badge variant="outline" size="xs" color="blue">{ep.active_connections} active</Badge>
                           {!ep.listening && <Badge color="red" size="xs">Stopped</Badge>}
                        </Group>
                      </Group>
                    </Accordion.Control>
                    <Accordion.Panel>
                      <Stack gap="xs" mt="xs">
                        {ep.last_error && (
                          <Alert color="red" variant="light" p="xs" title="Entrypoint Error" icon={<IconAlertTriangle size={16} />}>
                            <Text size="xs" ff="monospace">{ep.last_error}</Text>
                          </Alert>
                        )}
                        
                        <Text size="xs" fw={800} c="dimmed" style={{ textTransform: "uppercase" }}>Routes & Backend Chain</Text>
                        {ep.routes && ep.routes.length > 0 ? (
                          ep.routes.map(rt => <RouteTrace key={rt.id} route={rt} />)
                        ) : (
                          <Paper p="md" withBorder style={{ borderStyle: "dashed" }} bg="var(--mantine-color-gray-0)">
                            <Text size="sm" c="dimmed" ta="center">No routes attached to this entrypoint.</Text>
                          </Paper>
                        )}
                      </Stack>
                    </Accordion.Panel>
                  </Accordion.Item>
                ))}
              </Accordion>
              {(!data?.entrypoints || data.entrypoints?.length === 0) && (
                <Stack align="center" py="xl">
                  <Text c="dimmed" size="sm">No entrypoints configured.</Text>
                </Stack>
              )}
            </ScrollArea>
          </Card>

          {/* Recent TLS Errors */}
          <Card withBorder radius="lg" shadow="sm" p={0}>
            <Group p="md" bg="var(--mantine-color-default-hover)" justify="space-between">
              <Group gap="xs">
                <IconShield size={20} color="gray" />
                <Title order={4} fw={800}>Recent TLS Handshake Errors</Title>
              </Group>
              <Badge variant="filled" color="red" size="sm">{data?.recent_tls_errors?.length || 0}</Badge>
            </Group>
            <Divider />
            <ScrollArea h={400}>
              {data?.recent_tls_errors?.length === 0 ? (
                <Stack align="center" justify="center" h="100%" py="xl" gap="xs">
                  <IconCircleCheck size={48} color={theme.colors.teal[2]} />
                  <Text c="dimmed" size="sm" fw={500}>No recent TLS errors detected.</Text>
                </Stack>
              ) : (
                <Stack gap={0} p={0}>
                  {data?.recent_tls_errors?.map((err, i) => (
                    <Paper key={i} p="md" radius={0} className="hover-bg-default" style={{ borderBottom: "1px solid var(--mantine-color-gray-2)" }}>
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
