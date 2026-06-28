import React from 'react';
import { 
  Container, 
  Grid, 
  Text,
  Title, 
  Group, 
  Stack, 
  Badge, 
  Button,
  Paper,
  Alert, 
  Menu, 
  Loader, 
  Tabs,
  Select,
} from '@mantine/core';
import { 
  IconShieldCheck, 
  IconAdjustments, 
  IconInfoCircle, 
  IconX, 
  IconDownload,
  IconTrash,
  IconBox, 
  IconChevronDown,
  IconDashboard,
  IconSearch,
  IconActivity,
  IconBrain,
  IconAlertTriangle
} from '@tabler/icons-react';
import { useGateonStatus, apiFetch, useMetricsSnapshot } from '../hooks/useGateon';
import { notifications } from '@mantine/notifications';
import { Link } from '@tanstack/react-router';
import type { GlobalConfig, DeepScanStatus } from '../types/gateon';
import { format } from 'date-fns';

import { OverviewTab } from '../components/SecurityCenter/OverviewTab';
import { ThreatExplorerTab } from '../components/SecurityCenter/ThreatExplorerTab';
import { IncidentsTab } from '../components/SecurityCenter/IncidentsTab';
import { AnalyticsTab } from '../components/SecurityCenter/AnalyticsTab';
import { AIAdvisoryTab } from '../components/SecurityCenter/AIAdvisoryTab';
import { TimeDisplay } from '../components/TimeDisplay';
import { getThreatColor } from '../utils/security';
import { resolveTrafficRangeBounds, DAY_MS } from '../utils/dashboard';
import type { TrafficRangePreset } from '../utils/dashboard';

const TREND_RANGE_OPTIONS = [
  { value: 'last24h', label: 'Last 24 hours' },
  { value: 'last7d', label: 'Last 7 days' },
  { value: 'last30d', label: 'Last 30 days' },
  { value: 'thisMonth', label: 'This month' },
  { value: 'thisYear', label: 'This year' },
  { value: 'all', label: 'All' },
];

export default function SecurityCommandCenter() {
  const [page] = React.useState(1);
  const { data: metrics } = useMetricsSnapshot(10, page);
  const { data: status } = useGateonStatus();
  const [globalConfig, setGlobalConfig] = React.useState<GlobalConfig | null>(null);
  const [installing, setInstalling] = React.useState(false);
  const [uninstalling, setUninstalling] = React.useState(false);
  const [scanning, setScanning] = React.useState(false);
  const [scanStatus, setScanStatus] = React.useState<DeepScanStatus | null>(null);
  const pollIntervalRef = React.useRef<ReturnType<typeof setInterval> | null>(null);
  const [trendRange, setTrendRange] = React.useState<string>('last24h');

  const pollScanStatus = async () => {
    try {
      const res = await apiFetch("/v1/security/clamav/scan", { method: "POST" });
      const data = await res.json();
      if (data.success) {
        setScanStatus(data.status);
        setScanning(!!data.status?.is_running);
      }
    } catch (err) {
      console.error("Failed to poll scan status", err);
    }
  };

  React.useEffect(() => {
    pollScanStatus();
  }, []);

  React.useEffect(() => {
    if (scanning) {
      pollIntervalRef.current = setInterval(pollScanStatus, 5000);
    } else if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, [scanning]);

  const handleDeepScan = async () => {
    setScanning(true);
    try {
      const res = await apiFetch("/v1/security/clamav/scan", { method: "POST" });
      const data = await res.json();
      if (res.ok && data.success) {
        notifications.show({
          title: 'Deep Scan Started',
          message: 'A full system security scan has been initiated.',
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

  const handleUninstall = async () => {
    setUninstalling(true);
    try {
      const res = await apiFetch("/v1/security/clamav/uninstall", { method: "POST" });
      const data = await res.json();
      if (res.ok && data.success) {
        notifications.show({
          title: 'Uninstallation Started',
          message: 'ClamAV removal has been initiated. This might take a few minutes.',
          color: 'blue',
          icon: <IconShieldCheck size={16} />
        });
      } else {
        throw new Error(data.message || 'Failed to start uninstallation');
      }
    } catch (err: any) {
      notifications.show({
        title: 'Uninstallation Failed',
        message: err.message || 'Failed to start ClamAV uninstallation',
        color: 'red',
        icon: <IconX size={16} />
      });
    } finally {
      setUninstalling(false);
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
    return metrics.security.top_threat_types.map((t: any) => ({
      name: (t.label || '').toUpperCase(),
      value: t.value,
      color: getThreatColor(t.label)
    }));
  }, [metrics]);

  const totalThreats = React.useMemo(() => {
    return threatTypeData.reduce((acc: number, curr: any) => acc + curr.value, 0);
  }, [threatTypeData]);

  const countryData = React.useMemo(() => {
    if (!metrics?.security?.threats_by_country) return [];
    return metrics.security.threats_by_country.map((t: any) => ({
      country: t.label,
      threats: t.value
    }));
  }, [metrics]);

  const trendData = React.useMemo(() => {
    if (!metrics?.security?.attack_trend) return [];
    const bounds =
      trendRange === 'all'
        ? null
        : resolveTrafficRangeBounds('range', '', trendRange as TrafficRangePreset, '', '');
    // Use day-granular labels for spans wider than two days so month/year
    // selections stay readable.
    const spanMs = bounds ? bounds.endTs - bounds.startTs : Number.POSITIVE_INFINITY;
    const isWideSpan = spanMs > 2 * DAY_MS;
    return metrics.security.attack_trend
      .filter((t: any) => !bounds || (t.ts >= bounds.startTs && t.ts < bounds.endTs))
      .map((t: any) => {
        const date = new Date(t.ts);
        const valid = !isNaN(date.getTime());
        return {
          date: valid ? format(date, isWideSpan ? 'MMM d' : 'HH:mm') : 'N/A',
          threats: t.requests,
          fullDate: valid ? format(date, 'MMM d, HH:mm') : 'N/A',
        };
      });
  }, [metrics, trendRange]);

  return (
    <Container size="xl" py="md">
      <Stack gap="xl">
        {/* Header Section */}
        <Paper p="xl" radius="md" withBorder style={{ 
          background: 'linear-gradient(135deg, light-dark(var(--mantine-color-blue-0), var(--mantine-color-dark-8)) 0%, var(--mantine-color-body) 100%)',
          borderLeft: '4px solid var(--mantine-color-blue-filled)'
        }}>
          <Grid align="center">
            <Grid.Col span={{ base: 12, md: 8 }}>
              <Stack gap="xs">
                <Group gap="xs">
                  <Badge variant="dot" color="blue" size="sm">Autonomous Defense Active</Badge>
                  <TimeDisplay />
                </Group>
                <Title order={1} fw={900} style={{ letterSpacing: -1.5 }}>Security Hub</Title>
                <Text size="lg" c="dimmed" maw={600}>
                  Unified orchestration of kernel-level protection, behavioral analysis, and automated threat mitigation.
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
                    <Text size="10px" c="dimmed" ta="right" fw={500}>
                      Last scan: {format(new Date(scanStatus.last_scan), 'MMM d, HH:mm')}
                    </Text>
                  )}
                </Stack>
                {status?.clamav_installed && (
                  <Button
                    variant="subtle"
                    color="red"
                    leftSection={uninstalling ? <Loader size={16} color="red" /> : <IconTrash size={16} />}
                    onClick={handleUninstall}
                    disabled={uninstalling}
                  >
                    Uninstall ClamAV
                  </Button>
                )}
              </Group>
            </Grid.Col>
          </Grid>
        </Paper>

        {globalConfig?.waf?.malware_detection && status && !status.clamav_installed && (
          <Alert icon={<IconInfoCircle size="1rem" />} title="Malware Protection Degraded" color="red" variant="filled" radius="md">
            <Stack gap="xs">
              <Text size="sm">ClamAV service is not responding or not installed. Malware scanning is disabled.</Text>
              <Group gap="sm">
                <Menu shadow="md" width={200} position="bottom-start">
                  <Menu.Target>
                    <Button variant="white" size="xs" leftSection={installing ? <Loader size={14} color="blue" /> : <IconDownload size={14} />} rightSection={<IconChevronDown size={14} />} disabled={installing}>
                      Install Now
                    </Button>
                  </Menu.Target>
                  <Menu.Dropdown>
                    <Menu.Label>Installation Mode</Menu.Label>
                    <Menu.Item leftSection={<IconAdjustments size={14} />} onClick={() => handleInstall(1)}>Local</Menu.Item>
                    <Menu.Item leftSection={<IconBox size={14} />} onClick={() => handleInstall(2)}>Docker</Menu.Item>
                  </Menu.Dropdown>
                </Menu>
              </Group>
            </Stack>
          </Alert>
        )}

        <Tabs defaultValue="overview" variant="pills" radius="md">
          <Tabs.List mb="lg">
            <Tabs.Tab value="overview" leftSection={<IconDashboard size={16} />}>Overview</Tabs.Tab>
            <Tabs.Tab value="explorer" leftSection={<IconSearch size={16} />}>Threat Explorer</Tabs.Tab>
            <Tabs.Tab value="incidents" leftSection={<IconAlertTriangle size={16} />}>Incidents</Tabs.Tab>
            <Tabs.Tab value="analytics" leftSection={<IconActivity size={16} />}>Analytics & Trends</Tabs.Tab>
            <Tabs.Tab value="advisory" leftSection={<IconBrain size={16} />}>AI Advisory</Tabs.Tab>
          </Tabs.List>

          <Tabs.Panel value="overview">
            <OverviewTab 
              metrics={metrics}
              securityScore={securityScore}
              scoreColor={scoreColor}
              threatTypeData={threatTypeData}
              totalThreats={totalThreats}
            />
          </Tabs.Panel>

          <Tabs.Panel value="explorer">
            <ThreatExplorerTab />
          </Tabs.Panel>

          <Tabs.Panel value="incidents">
            <IncidentsTab />
          </Tabs.Panel>

          <Tabs.Panel value="analytics">
            <Group justify="flex-end" mb="md">
              <Select
                label="Trend range"
                size="xs"
                w={170}
                data={TREND_RANGE_OPTIONS}
                value={trendRange}
                onChange={(value) => setTrendRange(value ?? 'last24h')}
                allowDeselect={false}
              />
            </Group>
            <AnalyticsTab 
              metrics={metrics}
              trendData={trendData}
              countryData={countryData}
              threatTypeData={threatTypeData}
              totalThreats={totalThreats}
            />
          </Tabs.Panel>

          <Tabs.Panel value="advisory">
            <AIAdvisoryTab />
          </Tabs.Panel>
        </Tabs>
      </Stack>
    </Container>
  );
}

