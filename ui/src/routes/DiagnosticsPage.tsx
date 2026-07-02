import React, { useEffect, useState, useMemo, lazy, Suspense } from "react";
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
  Code,
  Tabs,
  Pagination,
  Center,
  Loader,
} from "@mantine/core";
import { getDiagnostics, applyRecommendation } from "../hooks/api";
import type { GetDiagnosticsResponse, RouteDiagnostic, MiddlewareDiagnostic, Anomaly, DependencyHealth } from "../types/gateon";
// Lazy-loaded: AnomalyMap pulls in Leaflet (the heavy `viz-vendor` chunk), so it
// is only fetched when the Diagnostics anomaly map is actually rendered.
const AnomalyMap = lazy(() => import("../components/Diagnostics/AnomalyMap"));
import TraceVisualizer from "../components/Diagnostics/TraceVisualizer";
import CORSValidator from "../components/Diagnostics/CORSValidator";
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
  IconShieldExclamation,
} from "@tabler/icons-react";
import { notifications } from "@mantine/notifications";
import { useDiagnostics } from "../hooks/useDiagnostics";

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

const SeverityStatCard: React.FC<{ label: string; count: number; color: string; icon: React.ReactNode }> = ({ label, count, color, icon }) => (
  <Paper withBorder p="xs" radius="md" style={{ flex: 1 }}>
    <Group gap="xs" wrap="nowrap">
      <ThemeIcon color={color} variant="light" size="sm">
        {icon}
      </ThemeIcon>
      <Box>
        <Text size="xs" c="dimmed" fw={700} style={{ textTransform: 'uppercase', fontSize: '9px', letterSpacing: 0.5 }}>{label}</Text>
        <Text fw={800} size="sm" style={{ lineHeight: 1 }}>{count}</Text>
      </Box>
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

const AnomalyCard: React.FC<{ anomaly: Anomaly; onApply: () => void; applying: boolean; onTrace: (ip: string) => void }> = ({ anomaly, onApply, applying, onTrace }) => {
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
    if (type.includes("geofence")) return <IconGlobe size={20} />;
    if (type.includes("integrity")) return <IconShield size={20} />;
    if (type.includes("honeypot")) return <IconAlertTriangle size={20} />;
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
                {(anomaly.type || "unknown").replace(/_/g, " ")}
              </Text>
              <Text size="xs" c="dimmed">
                {(() => {
                  const date = new Date(anomaly.timestamp);
                  return isNaN(date.getTime()) ? 'N/A' : date.toLocaleString();
                })()}
              </Text>
            </Stack>
          </Group>
          <Group gap="xs">
            {anomaly.mitigated && (
              <Badge color="teal" variant="light" size="xs" leftSection={<IconCircleCheck size={10} />}>
                Mitigated
              </Badge>
            )}
            <Tooltip label="Trace IP Route">
              <ActionIcon variant="light" color="blue" size="sm" onClick={() => onTrace(anomaly.source)}>
                <IconGlobe size={14} />
              </ActionIcon>
            </Tooltip>
            <Badge color={getSeverityColor(anomaly.severity)} variant="filled" size="xs">
              {anomaly.severity}
            </Badge>
          </Group>
        </Group>

        <Text size="sm" fw={500}>{anomaly.description}</Text>
        <Group gap={4}>
          <Text size="xs" c="dimmed">Source:</Text>
          <Code color="blue.0" c="blue.8" style={{ cursor: 'pointer' }} onClick={() => onTrace(anomaly.source)}>{anomaly.source}</Code>
        </Group>

        <Alert variant="light" color="indigo" radius="md" p="sm" icon={<IconRobot size={18} />}>
          <Stack gap="xs">
            <Text size="xs" fw={700}>System Recommendation:</Text>
            <Text size="xs">{anomaly.recommendation}</Text>
            {!anomaly.mitigated && (
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
            )}
          </Stack>
        </Alert>
      </Stack>
    </Paper>
  );
};

const DiagnosticsPage: React.FC = () => {
  const { data, isLoading: loading, error: queryError, refetch: fetchData } = useDiagnostics();
  const [applying, setApplying] = useState<string | null>(null);

  const error = queryError instanceof Error ? queryError.message : (queryError ? String(queryError) : null);

  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [visualizerOpened, setVisualizerOpened] = useState(false);

  const openVisualizer = (ip: string) => {
    if (!ip || ip === "-" || ip === "127.0.0.1") return;
    setSelectedIp(ip);
    setVisualizerOpened(true);
  };
  const theme = useMantineTheme();
  
  const sortedAnomalies = useMemo(() => {
    if (!data?.anomalies) return [];
    return [...data.anomalies].sort((a, b) => {
      const da = new Date(a.timestamp);
      const db = new Date(b.timestamp);
      const timeA = isNaN(da.getTime()) ? 0 : da.getTime();
      const timeB = isNaN(db.getTime()) ? 0 : db.getTime();
      if (timeA !== timeB) return timeB - timeA;
      return a.type.localeCompare(b.type) || a.source.localeCompare(b.source);
    });
  }, [data?.anomalies]);

  const activeThreats = useMemo(() => sortedAnomalies.filter(a => !a.mitigated), [sortedAnomalies]);
  const mitigatedThreats = useMemo(() => sortedAnomalies.filter(a => a.mitigated), [sortedAnomalies]);

  const THREATS_PER_PAGE = 6;
  const [activePage, setActivePage] = useState(1);
  const [mitigatedPage, setMitigatedPage] = useState(1);

  const activeTotalPages = Math.max(1, Math.ceil(activeThreats.length / THREATS_PER_PAGE));
  const mitigatedTotalPages = Math.max(1, Math.ceil(mitigatedThreats.length / THREATS_PER_PAGE));

  // Clamp current pages when the underlying lists shrink (e.g. after refresh).
  useEffect(() => {
    setActivePage(p => Math.min(p, activeTotalPages));
  }, [activeTotalPages]);
  useEffect(() => {
    setMitigatedPage(p => Math.min(p, mitigatedTotalPages));
  }, [mitigatedTotalPages]);

  const pagedActiveThreats = useMemo(
    () => activeThreats.slice((activePage - 1) * THREATS_PER_PAGE, activePage * THREATS_PER_PAGE),
    [activeThreats, activePage]
  );
  const pagedMitigatedThreats = useMemo(
    () => mitigatedThreats.slice((mitigatedPage - 1) * THREATS_PER_PAGE, mitigatedPage * THREATS_PER_PAGE),
    [mitigatedThreats, mitigatedPage]
  );

  const getStats = (threats: Anomaly[]) => {
    return {
      critical: threats.filter(t => t.severity.toLowerCase() === "critical").length,
      high: threats.filter(t => t.severity.toLowerCase() === "high").length,
      medium: threats.filter(t => t.severity.toLowerCase() === "medium").length,
      low: threats.filter(t => t.severity.toLowerCase() === "low").length,
    };
  };

  const activeStats = useMemo(() => getStats(activeThreats), [activeThreats]);
  const mitigatedStats = useMemo(() => getStats(mitigatedThreats), [mitigatedThreats]);

  const sortedDependencies = useMemo(() => {
    if (!data?.dependencies) return [];
    return [...data.dependencies].sort((a, b) => a.name.localeCompare(b.name));
  }, [data?.dependencies]);

  const sortedEntrypoints = useMemo(() => {
    if (!data?.entrypoints) return [];
    return [...data.entrypoints].sort((a, b) => a.name.localeCompare(b.name) || a.address.localeCompare(b.address));
  }, [data?.entrypoints]);

  const sortedTlsErrors = useMemo(() => {
    if (!data?.recent_tls_errors) return [];
    return [...data.recent_tls_errors].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }, [data?.recent_tls_errors]);

  const handleApplyRecommendation = async (anomaly: Anomaly) => {
    const key = `${anomaly.type}-${anomaly.source}`;
    try {
      setApplying(key);
      const res = await applyRecommendation(anomaly.type, anomaly.source, anomaly.id);
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
                {sortedDependencies.map((dep) => (
                   <DependencyBadge key={dep.name} dep={dep} />
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
            
            <Suspense fallback={<Loader size="sm" />}>
              <AnomalyMap anomalies={sortedAnomalies} onTrace={openVisualizer} />
            </Suspense>

            <Text size="sm" c="dimmed">
              Real-time heuristic analysis of traffic patterns and security events. 
              The engine identifies potential threats and provides actionable recommendations.
            </Text>

            <Tabs defaultValue="active" variant="pills" radius="md">
              <Tabs.List mb="md">
                <Tabs.Tab value="active" leftSection={<IconAlertTriangle size={14} />} color="red">
                  Active Threats ({activeThreats.length})
                </Tabs.Tab>
                <Tabs.Tab value="mitigated" leftSection={<IconCircleCheck size={14} />} color="teal">
                  Mitigated ({mitigatedThreats.length})
                </Tabs.Tab>
              </Tabs.List>

              <Tabs.Panel value="active">
                <Stack gap="md">
                  <SimpleGrid cols={{ base: 2, sm: 4 }} spacing="xs">
                    <SeverityStatCard label="Critical" count={activeStats.critical} color="red" icon={<IconShieldExclamation size={14} />} />
                    <SeverityStatCard label="High" count={activeStats.high} color="orange" icon={<IconShield size={14} />} />
                    <SeverityStatCard label="Medium" count={activeStats.medium} color="yellow" icon={<IconInfoCircle size={14} />} />
                    <SeverityStatCard label="Low" count={activeStats.low} color="blue" icon={<IconInfoCircle size={14} />} />
                  </SimpleGrid>

                  {activeThreats.length > 0 ? (
                    <>
                      <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
                        {pagedActiveThreats.map((a) => (
                          <AnomalyCard 
                            key={`${a.type}-${a.source}-${a.timestamp}`} 
                            anomaly={a} 
                            onApply={() => handleApplyRecommendation(a)}
                            applying={applying === `${a.type}-${a.source}`}
                            onTrace={openVisualizer}
                          />
                        ))}
                      </SimpleGrid>
                      {activeTotalPages > 1 && (
                        <Center mt="xs">
                          <Pagination
                            total={activeTotalPages}
                            value={activePage}
                            onChange={setActivePage}
                            color="red"
                            size="sm"
                            radius="md"
                          />
                        </Center>
                      )}
                    </>
                  ) : (
                    <Paper p="xl" withBorder radius="lg" style={{ borderStyle: "dashed" }} bg="var(--mantine-color-gray-0)">
                      <Stack align="center" gap="xs">
                        <IconCircleCheck size={40} color={theme.colors.teal[3]} />
                        <Text fw={700} c="teal">No Active Threats</Text>
                        <Text size="xs" c="dimmed">No immediate threats detected in your network.</Text>
                      </Stack>
                    </Paper>
                  )}
                </Stack>
              </Tabs.Panel>

              <Tabs.Panel value="mitigated">
                <Stack gap="md">
                  <SimpleGrid cols={{ base: 2, sm: 4 }} spacing="xs">
                    <SeverityStatCard label="Critical" count={mitigatedStats.critical} color="red" icon={<IconShieldExclamation size={14} />} />
                    <SeverityStatCard label="High" count={mitigatedStats.high} color="orange" icon={<IconShield size={14} />} />
                    <SeverityStatCard label="Medium" count={mitigatedStats.medium} color="yellow" icon={<IconInfoCircle size={14} />} />
                    <SeverityStatCard label="Low" count={mitigatedStats.low} color="blue" icon={<IconInfoCircle size={14} />} />
                  </SimpleGrid>

                  {mitigatedThreats.length > 0 ? (
                    <>
                      <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
                        {pagedMitigatedThreats.map((a) => (
                          <AnomalyCard 
                            key={`${a.type}-${a.source}-${a.timestamp}`} 
                            anomaly={a} 
                            onApply={() => handleApplyRecommendation(a)}
                            applying={applying === `${a.type}-${a.source}`}
                            onTrace={openVisualizer}
                          />
                        ))}
                      </SimpleGrid>
                      {mitigatedTotalPages > 1 && (
                        <Center mt="xs">
                          <Pagination
                            total={mitigatedTotalPages}
                            value={mitigatedPage}
                            onChange={setMitigatedPage}
                            color="teal"
                            size="sm"
                            radius="md"
                          />
                        </Center>
                      )}
                    </>
                  ) : (
                    <Paper p="xl" withBorder radius="lg" style={{ borderStyle: "dashed" }} bg="var(--mantine-color-gray-0)">
                      <Stack align="center" gap="xs">
                        <IconInfoCircle size={40} color={theme.colors.gray[3]} />
                        <Text fw={700} c="dimmed">No Mitigated Threats</Text>
                        <Text size="xs" c="dimmed">History of mitigated threats will appear here.</Text>
                      </Stack>
                    </Paper>
                  )}
                </Stack>
              </Tabs.Panel>
            </Tabs>
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
                {sortedEntrypoints.map((ep) => (
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
                  {sortedTlsErrors.map((err) => (
                    <Paper key={`${err.timestamp}-${err.remote_addr}-${err.entrypoint_id}`} p="md" radius={0} className="hover-bg-default" style={{ borderBottom: "1px solid var(--mantine-color-gray-2)" }}>
                      <Group justify="space-between" mb={4}>
                        <Group gap={6}>
                          <IconClock size={12} color={theme.colors.gray[5]} />
                          <Text size="xs" c="dimmed" fw={700} ff="monospace">
                            {(() => {
                              const date = new Date(err.timestamp);
                              return isNaN(date.getTime()) ? 'N/A' : date.toLocaleTimeString();
                            })()}
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

        {/* Diagnostic Tools */}
        <Card withBorder radius="lg" shadow="sm" p="lg">
          <Stack gap="md">
            <Group justify="space-between">
              <Group gap="xs">
                <IconShield size={24} color={theme.colors.blue[6]} />
                <Title order={3} fw={900}>Diagnostic Tools</Title>
              </Group>
              <Badge variant="light" color="blue" size="lg">Self-Service Validation</Badge>
            </Group>

            <Tabs defaultValue="cors" variant="outline" radius="md">
              <Tabs.List mb="md">
                <Tabs.Tab value="cors" leftSection={<IconShield size={14} />}>
                  CORS Validator
                </Tabs.Tab>
              </Tabs.List>

              <Tabs.Panel value="cors">
                <CORSValidator />
              </Tabs.Panel>
            </Tabs>
          </Stack>
        </Card>
      </Stack>
      <TraceVisualizer 
        opened={visualizerOpened} 
        onClose={() => setVisualizerOpened(false)} 
        targetIp={selectedIp || ""} 
      />
    </Box>
  );
};

export default DiagnosticsPage;
