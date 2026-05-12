import React from 'react';
import { Container, Grid, Card, Text, Title, Group, Stack, Badge, ThemeIcon, SimpleGrid, Button, ActionIcon, Tooltip, Table, Box, Paper, Avatar, RingProgress, Center, Alert, Menu, Loader } from '@mantine/core';
import { DonutChart, LineChart, BarChart } from '@mantine/charts';
import { IconShieldCheck, IconShieldExclamation, IconAlertTriangle, IconActivity, IconBell, IconHistory, IconFingerprint, IconWorld, IconLock, IconRefresh, IconSearch, IconAdjustments, IconTarget, IconExternalLink, IconUserCheck, IconGhost, IconShieldOff, IconArrowUpRight, IconArrowDownRight, IconInfoCircle, IconMapPin, IconClock, IconX, IconDownload, IconBox, IconChevronDown } from '@tabler/icons-react';
import { useSecurityThreats, useGateonStatus, apiFetch, useMetricsSnapshot } from '../hooks/useGateon';
import { notifications } from '@mantine/notifications';
import { ReputationMonitor } from '../components/ReputationMonitor';
import { Link } from '@tanstack/react-router';
import type { GlobalConfig, DeepScanStatus } from '../types/gateon';
import { format } from 'date-fns';

export default function SecurityCommandCenter() {
  const { data: metrics, isLoading: metricsLoading } = useMetricsSnapshot();
  const { data: status } = useGateonStatus();
  const { refetch: refetchMetrics } = useMetricsSnapshot();
  const [globalConfig, setGlobalConfig] = React.useState<GlobalConfig | null>(null);
  const [unmitigating, setUnmitigating] = React.useState<string | null>(null);
  const [installing, setInstalling] = React.useState(false);
  const [scanning, setScanning] = React.useState(false);
  const [scanStatus, setScanStatus] = React.useState<DeepScanStatus | null>(null);

  const pollScanStatus = async () => {
    try {
      const res = await apiFetch("/v1/security/clamav/scan", { method: "POST" });
      const data = await res.json();
      if (data.success) {
        setScanStatus(data.status);
        if (data.status?.is_running) {
          setScanning(true);
        } else {
          setScanning(false);
        }
      }
    } catch (err) {
      console.error("Failed to poll scan status", err);
    }
  };

  React.useEffect(() => {
    pollScanStatus();
  }, []);

  React.useEffect(() => {
    let interval: any;
    if (scanning) {
      interval = setInterval(pollScanStatus, 5000);
    }
    return () => clearInterval(interval);
  }, [scanning]);

  const handleDeepScan = async () => {
    setScanning(true);
    try {
      const res = await apiFetch("/v1/security/clamav/scan", {
        method: "POST"
      });
      const data = await res.json();
      if (res.ok && data.success) {
        notifications.show({
          title: 'Deep Scan Started',
          message: 'A full system security scan has been initiated. You will be notified of any threats found.',
          color: 'blue',
          icon: <IconShieldCheck size={16} />
        });
      } else {
        throw new Error(data.message || 'Failed to start deep scan');
      }
    } catch (err: any) {
      notifications.show({
        title: 'Scan Failed',
        message: err.message || 'Failed to start security scan',
        color: 'red',
        icon: <IconX size={16} />
      });
    } finally {
      setScanning(false);
    }
  };

  const handleInstall = async (mode: number) => {
    setInstalling(true);
    try {
      const res = await apiFetch("/v1/security/clamav/install", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        notifications.show({
          title: 'Installation Started',
          message: 'ClamAV installation has been initiated. This might take a few minutes.',
          color: 'blue',
          icon: <IconShieldCheck size={16} />
        });
      } else {
        throw new Error(data.message || 'Failed to start installation');
      }
    } catch (err: any) {
      notifications.show({
        title: 'Installation Failed',
        message: err.message || 'Failed to start ClamAV installation',
        color: 'red',
        icon: <IconX size={16} />
      });
    } finally {
      setInstalling(false);
    }
  };

  const handleUnmitigate = async (ip: string) => {
    setUnmitigating(ip);
    try {
      const res = await apiFetch("/v1/remove-mitigated-threat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source: ip })
      });
      const data = await res.json();
      if (data.success) {
        notifications.show({
          title: 'Mitigation Removed',
          message: `IP ${ip} has been unmitigated and added to the whitelist exception.`,
          color: 'green',
          icon: <IconShieldCheck size={16} />
        });
        refetchMetrics();
      } else {
        throw new Error(data.message);
      }
    } catch (err: any) {
      notifications.show({
        title: 'Error',
        message: err.message || 'Failed to remove mitigation',
        color: 'red',
        icon: <IconX size={16} />
      });
    } finally {
      setUnmitigating(null);
    }
  };

  React.useEffect(() => {
    apiFetch("/v1/global")
      .then(r => r.ok ? r.json() : null)
      .then(cfg => setGlobalConfig(cfg))
      .catch(() => {});
  }, []);

  const securityScore = React.useMemo(() => {
    if (!metrics) return 100;
    const base = 100;
    const penalty = (metrics.active_suspicious_sessions * 2) + 
                    (metrics.active_unverified_clients * 0.5) +
                    (metrics.active_anomaly_score_average * 0.1);
    return Math.max(Math.round(base - penalty), 0);
  }, [metrics]);

  const scoreColor = securityScore > 85 ? 'teal' : securityScore > 65 ? 'blue' : securityScore > 40 ? 'orange' : 'red';

  const threatTypeData = React.useMemo(() => {
    if (!metrics?.security?.top_threat_types) return [];
    return metrics.security.top_threat_types.map(t => ({
      name: (t.label || '').toUpperCase(),
      value: t.value,
      color: getThreatColor(t.label)
    }));
  }, [metrics]);

  const totalThreats = React.useMemo(() => {
    return threatTypeData.reduce((acc, curr) => acc + curr.value, 0);
  }, [threatTypeData]);

  const countryData = React.useMemo(() => {
    if (!metrics?.security?.threats_by_country) return [];
    return metrics.security.threats_by_country.map(t => ({
      country: t.label,
      threats: t.value
    }));
  }, [metrics]);

  const trendData = React.useMemo(() => {
    if (!metrics?.security?.attack_trend) return [];
    return metrics.security.attack_trend.map(t => {
      const date = new Date(t.ts);
      return {
        date: isNaN(date.getTime()) ? 'N/A' : format(date, 'HH:mm'),
        threats: t.requests
      };
    });
  }, [metrics]);

  return (
    <Container size="xl" py="md">
      <Stack gap="xl">
        {/* Header Section */}
        <Paper p="xl" radius="md" withBorder style={{ 
          background: 'linear-gradient(135deg, var(--mantine-color-blue-light) 0%, var(--mantine-color-body) 100%)',
          borderLeft: '4px solid var(--mantine-color-blue-filled)'
        }}>
          <Grid align="center">
            <Grid.Col span={{ base: 12, md: 8 }}>
              <Stack gap="xs">
                <Group gap="xs">
                  <Badge variant="dot" color="blue" size="sm">Autonomous Defense Active</Badge>
                  <Text size="xs" c="dimmed">{format(new Date(), 'PPP p')}</Text>
                </Group>
                <Title order={1} fw={900} style={{ letterSpacing: -1.5 }}>Security Command Center</Title>
                <Text size="lg" c="dimmed" maw={600}>
                  Real-time orchestration of kernel-level protection, behavioral analysis, and automated threat mitigation.
                </Text>
              </Stack>
            </Grid.Col>
            <Grid.Col span={{ base: 12, md: 4 }}>
              <Group justify="flex-end">
                <Button variant="white" color="blue" leftSection={<IconAdjustments size={16} />} component={Link} to="/settings">
                  Orchestration Rules
                </Button>
                <Stack gap={2}>
                  <Button 
                    variant="filled" 
                    color="blue" 
                    leftSection={scanning ? <Loader size={16} color="white" /> : <IconShieldCheck size={16} />}
                    onClick={handleDeepScan}
                    disabled={scanning || !status?.clamav_installed}
                  >
                    {scanning ? 'Scanning...' : 'Deep Scan'}
                  </Button>
                  {scanStatus?.last_scan && !scanning && (
                    <Stack gap={0}>
                      <Text size="10px" c="dimmed" ta="right" fw={500}>
                        Last scan: {format(new Date(scanStatus.last_scan), 'MMM d, HH:mm')}
                      </Text>
                      {scanStatus.last_result && scanStatus.last_result !== "Clean" && (
                        <Text size="10px" c="red" ta="right" fw={700}>
                          {scanStatus.last_result}
                        </Text>
                      )}
                    </Stack>
                  )}
                </Stack>
              </Group>
            </Grid.Col>
          </Grid>
        </Paper>

        {globalConfig?.waf?.malware_detection && status && !status.clamav_installed && (
          <Alert icon={<IconInfoCircle size="1rem" />} title="Malware Protection Degraded" color="red" variant="filled" radius="md">
            <Stack gap="xs">
              <Text size="sm">
                Malware detection is enabled in your configuration, but the ClamAV service is not responding or not installed on this server.
                Scanning of uploaded files is currently non-functional.
              </Text>
              <Group gap="sm">
                <Menu shadow="md" width={200} position="bottom-start">
                  <Menu.Target>
                    <Button 
                      variant="white" 
                      size="xs" 
                      leftSection={installing ? <Loader size={14} color="blue" /> : <IconDownload size={14} />}
                      rightSection={<IconChevronDown size={14} />}
                      disabled={installing}
                    >
                      Install Now
                    </Button>
                  </Menu.Target>

                  <Menu.Dropdown>
                    <Menu.Label>Choose Installation Mode</Menu.Label>
                    <Menu.Item 
                      leftSection={<IconAdjustments size={14} />} 
                      onClick={() => handleInstall(1)}
                    >
                      Local Installation
                    </Menu.Item>
                    <Menu.Item 
                      leftSection={<IconBox size={14} />} 
                      onClick={() => handleInstall(2)}
                    >
                      Docker Container
                    </Menu.Item>
                  </Menu.Dropdown>
                </Menu>
                <Button variant="outline" color="white" size="xs" component={Link} to="/settings">
                  Go to Settings
                </Button>
              </Group>
            </Stack>
          </Alert>
        )}

        {/* Stats Overview */}
        <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }}>
          <Card withBorder radius="md" p="md">
            <Group justify="space-between">
              <Stack gap={0}>
                <Text size="xs" c="dimmed" fw={700} tt="uppercase">Security Posture</Text>
                <Title order={3}>{securityScore}%</Title>
              </Stack>
              <RingProgress
                size={60}
                thickness={6}
                roundCaps
                sections={[{ value: securityScore, color: scoreColor }]}
                label={
                  <Center>
                    <IconShieldCheck size={18} color={`var(--mantine-color-${scoreColor}-6)`} />
                  </Center>
                }
              />
            </Group>
            <Group gap={4} mt="sm">
              <IconInfoCircle size={14} color="gray" />
              <Text size="xs" c="dimmed">
                {securityScore > 90 ? 'Optimal configuration' : 'Vulnerabilities detected'}
              </Text>
            </Group>
          </Card>

          <Card withBorder radius="md" p="md">
            <Group justify="space-between">
              <Stack gap={0}>
                <Text size="xs" c="dimmed" fw={700} tt="uppercase">Active Mitigations</Text>
                <Title order={3}>{metrics?.security?.recent_anomalies?.filter(a => a.mitigated).length || 0}</Title>
              </Stack>
              <ThemeIcon size="xl" color="red" variant="light" radius="md">
                <IconShieldOff size={24} />
              </ThemeIcon>
            </Group>
            <Group gap={4} mt="sm">
              <IconActivity size={14} color="red" />
              <Text size="xs" c="dimmed">
                Recently mitigated threats
              </Text>
            </Group>
          </Card>

          <Card withBorder radius="md" p="md">
            <Group justify="space-between">
              <Stack gap={0}>
                <Text size="xs" c="dimmed" fw={700} tt="uppercase">Mitigated Today</Text>
                <Title order={3}>{metrics?.middleware?.mitigated_threats?.reduce((a, b) => a + b.value, 0) || 0}</Title>
              </Stack>
              <ThemeIcon color="teal" variant="light" size="lg" radius="md">
                <IconShieldCheck size={20} />
              </ThemeIcon>
            </Group>
            <Group gap={4} mt="sm">
              <IconArrowUpRight size={14} color="teal" />
              <Text size="xs" c="teal" fw={700}>+12%</Text>
              <Text size="xs" c="dimmed">vs yesterday</Text>
            </Group>
          </Card>

          <Card withBorder radius="md" p="md">
            <Group justify="space-between">
              <Stack gap={0}>
                <Text size="xs" c="dimmed" fw={700} tt="uppercase">Active Threats</Text>
                <Title order={3}>{metrics?.active_suspicious_sessions || 0}</Title>
              </Stack>
              <ThemeIcon color="red" variant="light" size="lg" radius="md">
                <IconAlertTriangle size={20} />
              </ThemeIcon>
            </Group>
            <Group gap={4} mt="sm">
              <IconArrowDownRight size={14} color="red" />
              <Text size="xs" c="red" fw={700}>-5%</Text>
              <Text size="xs" c="dimmed">active mitigations</Text>
            </Group>
          </Card>

          <Card withBorder radius="md" p="md">
            <Group justify="space-between">
              <Stack gap={0}>
                <Text size="xs" c="dimmed" fw={700} tt="uppercase">Reputation Score</Text>
                <Title order={3}>Good</Title>
              </Stack>
              <ThemeIcon color="blue" variant="light" size="lg" radius="md">
                <IconFingerprint size={20} />
              </ThemeIcon>
            </Group>
            <Group gap={4} mt="sm">
              <Text size="xs" c="dimmed">Based on global fingerprinting</Text>
            </Group>
          </Card>
        </SimpleGrid>

        {/* Charts Section */}
        <Grid>
          <Grid.Col span={{ base: 12, lg: 8 }}>
            <Card withBorder radius="md" style={{ height: '100%' }}>
              <Group justify="space-between" mb="xl">
                <Stack gap={0}>
                  <Title order={4}>Attack Trend</Title>
                  <Text size="xs" c="dimmed">Real-time attempt monitoring across all entrypoints</Text>
                </Stack>
                <Badge variant="light">Last 24 Hours</Badge>
              </Group>
              <Box h={300} w="100%" style={{ minWidth: 0 }}>
                <LineChart
                  h={300}
                  data={trendData}
                  dataKey="date"
                  series={[{ name: 'threats', color: 'red.6', label: 'Blocked Attacks' }]}
                  curveType="monotone"
                  withDots={false}
                  gridAxis="xy"
                  tickLine="xy"
                />
              </Box>
            </Card>
          </Grid.Col>
          <Grid.Col span={{ base: 12, lg: 4 }}>
            <Card withBorder radius="md" style={{ height: '100%' }}>
              <Title order={4} mb="xl" ta="center">Threat Distribution</Title>
              <Center h={280} w="100%" style={{ minWidth: 0 }}>
                <DonutChart
                  data={threatTypeData}
                  withLabelsLine
                  labelsType="percent"
                  withLabels
                  size={210}
                  thickness={30}
                  paddingAngle={5}
                  strokeWidth={2}
                  withTooltip
                  chartLabel={`${totalThreats} Total`}
                />
              </Center>
              <Stack gap="xs" mt="md">
                {threatTypeData.slice(0, 3).map((item) => (
                  <Group key={item.name} justify="space-between">
                    <Group gap="xs">
                      <Box w={10} h={10} style={{ borderRadius: '50%', backgroundColor: `var(--mantine-color-${item.color.split('.')[0]}-7)` }} />
                      <Text size="sm">{item.name}</Text>
                    </Group>
                    <Text size="sm" fw={700}>{item.value}</Text>
                  </Group>
                ))}
              </Stack>
            </Card>
          </Grid.Col>
        </Grid>

        {/* Lower Section */}
        <Grid>
          <Grid.Col span={{ base: 12, lg: 4 }}>
            <Stack gap="md">
              <Card withBorder radius="md">
                <Title order={4} mb="md">Top Attack Sources</Title>
                <Table variant="vertical">
                  <Table.Tbody>
                    {metrics?.security?.top_threat_sources?.map((s) => (
                      <Table.Tr key={s.label}>
                        <Table.Td>
                          <Group gap="sm">
                            <Avatar size="sm" radius="xl" color="red"><IconMapPin size={14} /></Avatar>
                            <Stack gap={0}>
                              <Text size="sm" fw={700}>{s.label}</Text>
                              <Text size="xs" c="dimmed">ASN: Unknown</Text>
                            </Stack>
                          </Group>
                        </Table.Td>
                        <Table.Td ta="right">
                          <Badge color="red" variant="light">{s.value}</Badge>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                    {(!metrics?.security?.top_threat_sources || metrics.security.top_threat_sources.length === 0) && (
                      <Table.Tr><Table.Td><Text size="sm" c="dimmed">No sources detected yet.</Text></Table.Td></Table.Tr>
                    )}
                  </Table.Tbody>
                </Table>
              </Card>

              <Card withBorder radius="md">
                <Title order={4} mb="md">Geographic Hotspots</Title>
                <Box h={200} w="100%" style={{ minWidth: 0 }}>
                  <BarChart
                    h={200}
                    data={countryData}
                    dataKey="country"
                    series={[{ name: 'threats', color: 'blue.6' }]}
                    orientation="vertical"
                    gridAxis="none"
                    yAxisProps={{ width: 40 }}
                  />
                </Box>
              </Card>
            </Stack>
          </Grid.Col>

          <Grid.Col span={{ base: 12, lg: 8 }}>
            <Stack gap="md">
              <Card withBorder radius="md">
                <Group justify="space-between" mb="md">
                  <Title order={4}>Recent Anomalies & Security Events</Title>
                  <Button size="xs" variant="light" leftSection={<IconRefresh size={14} />}>Refresh</Button>
                </Group>
                <Table.ScrollContainer minWidth={600}>
                  <Table verticalSpacing="md" highlightOnHover>
                    <Table.Thead>
                      <Table.Tr>
                        <Table.Th>Event / Type</Table.Th>
                        <Table.Th>Source</Table.Th>
                        <Table.Th>Severity</Table.Th>
                        <Table.Th>Action</Table.Th>
                        <Table.Th>Time</Table.Th>
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {metrics?.security?.recent_anomalies?.map((a) => (
                        <Table.Tr key={a.id}>
                          <Table.Td>
                            <Stack gap={0}>
                              <Text size="sm" fw={700}>{(a.type || 'Unknown').toUpperCase()}</Text>
                              <Text size="xs" c="dimmed" maw={300} truncate="end">{a.details}</Text>
                            </Stack>
                          </Table.Td>
                          <Table.Td>
                            <Group gap={4}>
                              <Text size="xs" ff="monospace">{a.country_code || 'XX'}</Text>
                              <Text size="sm" fw={500}>{a.source_ip}</Text>
                            </Group>
                          </Table.Td>
                          <Table.Td>
                            <Badge color={getSeverityColor(a.severity)} variant="filled" size="sm">
                              {a.severity}
                            </Badge>
                          </Table.Td>
                          <Table.Td>
                            <Group gap="xs">
                              <Group gap={4}>
                                <ThemeIcon size="xs" color={a.mitigated ? "red" : "gray"} variant="subtle">
                                  {a.mitigated ? <IconShieldOff size={12} /> : <IconLock size={12} />}
                                </ThemeIcon>
                                <Text size="xs" fw={a.mitigated ? 600 : 400} c={a.mitigated ? "red" : "inherit"}>
                                  {a.action_taken || 'Detected'}
                                </Text>
                              </Group>
                              {a.mitigated && (
                                <Tooltip label="Tag as unmitigated (Unshun IP)">
                                  <ActionIcon 
                                    size="sm" 
                                    variant="light" 
                                    color="blue" 
                                    onClick={() => handleUnmitigate(a.source_ip)}
                                    loading={unmitigating === a.source_ip}
                                  >
                                    <IconUserCheck size={14} />
                                  </ActionIcon>
                                </Tooltip>
                              )}
                            </Group>
                          </Table.Td>
                          <Table.Td>
                            <Text size="xs" c="dimmed">
                              {(() => {
                                const date = new Date(a.timestamp);
                                return isNaN(date.getTime()) ? 'N/A' : format(date, 'HH:mm:ss');
                              })()}
                            </Text>
                          </Table.Td>
                        </Table.Tr>
                      ))}
                      {(!metrics?.security?.recent_anomalies || metrics.security.recent_anomalies.length === 0) && (
                        <Table.Tr>
                          <Table.Td colSpan={5} ta="center" py="xl" c="dimmed">No recent security events.</Table.Td>
                        </Table.Tr>
                      )}
                    </Table.Tbody>
                  </Table>
                </Table.ScrollContainer>
              </Card>

              <SimpleGrid cols={{ base: 1, md: 2 }}>
                 <ReputationMonitor />
                 <Card withBorder radius="md">
                    <Title order={4} mb="md">Active Playbooks</Title>
                    <Stack gap="xs">
                      {globalConfig?.alerting?.playbooks?.slice(0, 3).map((pb) => (
                        <Paper key={pb.id} withBorder p="xs" radius="sm">
                          <Group justify="space-between">
                            <Stack gap={2}>
                              <Text size="sm" fw={600}>{pb.name}</Text>
                              <Text size="xs" c="dimmed">
                                {pb.event_type} score ≥ {pb.threshold}
                              </Text>
                            </Stack>
                            <Badge size="sm" variant="light" color={pb.action === 'block' ? 'red' : 'blue'}>
                              {(pb.action || 'notify').toUpperCase()}
                            </Badge>
                          </Group>
                        </Paper>
                      ))}
                      <Button variant="light" size="xs" fullWidth mt="sm" component={Link} to="/settings">
                        Manage All Playbooks
                      </Button>
                    </Stack>
                 </Card>
              </SimpleGrid>
            </Stack>
          </Grid.Col>
        </Grid>
      </Stack>
    </Container>
  );
}

function getThreatColor(type: string) {
  const t = (type || '').toLowerCase();
  if (t.includes('waf') || t.includes('sqli') || t.includes('xss')) return 'red.7';
  if (t.includes('bot') || t.includes('scanner')) return 'orange.7';
  if (t.includes('geoip')) return 'blue.7';
  if (t.includes('ddos') || t.includes('flood')) return 'grape.7';
  if (t.includes('brute')) return 'yellow.7';
  return 'cyan.7';
}

function getSeverityColor(sev: string) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'red';
  if (s === 'medium') return 'orange';
  if (s === 'low') return 'blue';
  return 'gray';
}

