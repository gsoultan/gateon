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
  Modal,
  PasswordInput,
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
  IconAlertTriangle,
  IconCode,
  IconBolt
} from '@tabler/icons-react';
import { useGateonStatus, apiFetch, useMetricsSnapshot, installClamav, uninstallClamav } from '../hooks/useGateon';
import { notifications } from '@mantine/notifications';
import { Link } from '@tanstack/react-router';
import { usePermissions } from '../hooks/usePermissions';
import type { GlobalConfig, DeepScanStatus } from '../types/gateon';
import { format } from 'date-fns';

import { OverviewTab } from '../components/SecurityCenter/OverviewTab';
import { ThreatExplorerTab } from '../components/SecurityCenter/ThreatExplorerTab';
import { IncidentsTab } from '../components/SecurityCenter/IncidentsTab';
import { AnalyticsTab } from '../components/SecurityCenter/AnalyticsTab';
import { AIAdvisoryTab } from '../components/SecurityCenter/AIAdvisoryTab';
import { WAFRulesTab } from '../components/SecurityCenter/WAFRulesTab';
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
  const { canWrite, isViewer } = usePermissions();
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
  const [sudoOpened, setSudoOpened] = React.useState(false);
  const [pendingMode, setPendingMode] = React.useState<number | null>(null);
  const [sudoPassword, setSudoPassword] = React.useState("");

  const pollScanStatus = async () => {
    try {
      const res = await apiFetch("/v1/security/clamav/scan", { method: "POST" });
      const data = await res.json();
      if (data.success) {
        setScanStatus(data.status);
        setScanning(!!data.status?.isRunning);
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

  const handleInstall = async (mode: number, password?: string) => {
    if (mode === 1 && !password) {
      setPendingMode(mode);
      setSudoOpened(true);
      return;
    }

    setInstalling(true);
    setSudoOpened(false);
    try {
      const data = await installClamav({ mode, sudoPassword: password });
      if (data.success) {
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

  const handleUninstall = async (password?: string) => {
    const mode = globalConfig?.waf?.clamav?.installationMode;
    if (mode === 1 && !password) {
      setPendingMode(3); // 3 for uninstall
      setSudoOpened(true);
      return;
    }

    setUninstalling(true);
    setSudoOpened(false);
    try {
      const data = await uninstallClamav({ sudoPassword: password });
      if (data.success) {
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

  const handleSudoConfirm = () => {
    if (pendingMode === 3) {
      handleUninstall(sudoPassword);
    } else if (pendingMode) {
      handleInstall(pendingMode, sudoPassword);
    }
    setSudoPassword("");
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
    const penalty = ((Number(metrics.activeSuspiciousSessions) || 0) * 2) + 
                    ((Number(metrics.activeUnverifiedClients) || 0) * 0.5) +
                    ((Number(metrics.activeAnomalyScoreAverage) || 0) * 0.1);
    const score = Math.max(Math.round(base - penalty), 0);
    return isNaN(score) ? 100 : score;
  }, [metrics]);

  const scoreColor = securityScore > 85 ? 'teal' : securityScore > 65 ? 'blue' : securityScore > 40 ? 'orange' : 'red';

  const threatTypeData = React.useMemo(() => {
    if (!metrics?.security?.topThreatTypes) return [];
    return metrics.security.topThreatTypes.map((t: any) => ({
      name: (t.label || '').toUpperCase(),
      value: t.value,
      color: getThreatColor(t.label)
    }));
  }, [metrics]);

  const totalThreats = React.useMemo(() => {
    return threatTypeData.reduce((acc: number, curr: any) => acc + curr.value, 0);
  }, [threatTypeData]);

  const countryData = React.useMemo(() => {
    if (!metrics?.security?.threatsByCountry) return [];
    return metrics.security.threatsByCountry.map((t: any) => ({
      country: t.label,
      threats: t.value
    }));
  }, [metrics]);

  const trendData = React.useMemo(() => {
    if (!metrics?.security?.attackTrend) return [];
    const bounds =
      trendRange === 'all'
        ? null
        : resolveTrafficRangeBounds('range', '', trendRange as TrafficRangePreset, '', '');
    // Use day-granular labels for spans wider than two days so month/year
    // selections stay readable.
    const spanMs = bounds ? bounds.endTs - bounds.startTs : Number.POSITIVE_INFINITY;
    const isWideSpan = spanMs > 2 * DAY_MS;
    return metrics.security.attackTrend
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
                  {globalConfig?.titan?.enabled && (
                    <Badge variant="filled" color="orange" size="sm" leftSection={<IconBolt size={12} />}>TITAN EVOLUTION</Badge>
                  )}
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
                {!isViewer && (
                  <Button variant="white" color="blue" leftSection={<IconAdjustments size={16} />} component={Link} to="/settings">
                    Orchestration Rules
                  </Button>
                )}
                <Stack gap={2}>
                  <Button 
                    variant="filled" 
                    color="blue" 
                    leftSection={scanning ? <Loader size={16} color="white" /> : <IconShieldCheck size={16} />}
                    onClick={handleDeepScan}
                    disabled={scanning || !status?.clamavInstalled || !canWrite}
                  >
                    {scanning ? 'Scanning...' : 'Deep Scan'}
                  </Button>
                  {scanStatus?.lastScan && !scanning && (
                    <Text size="10px" c="dimmed" ta="right" fw={500}>
                      Last scan: {format(new Date(scanStatus.lastScan), 'MMM d, HH:mm')}
                    </Text>
                  )}
                </Stack>
                {status?.clamavInstalled && (
                  <Button
                    variant="subtle"
                    color="red"
                    leftSection={uninstalling ? <Loader size={16} color="red" /> : <IconTrash size={16} />}
                    onClick={() => handleUninstall()}
                    disabled={uninstalling || !canWrite}
                  >
                    Uninstall ClamAV
                  </Button>
                )}
              </Group>
            </Grid.Col>
          </Grid>
        </Paper>

        {globalConfig?.waf?.malwareDetection && status && !status.clamavInstalled && (
          <Alert icon={<IconInfoCircle size="1rem" />} title="Malware Protection Degraded" color="red" variant="filled" radius="md">
            <Stack gap="xs">
              <Text size="sm">ClamAV service is not responding or not installed. Malware scanning is disabled.</Text>
              <Group gap="sm">
                <Menu shadow="md" width={200} position="bottom-start">
                  <Menu.Target>
                    <Button variant="white" size="xs" leftSection={installing ? <Loader size={14} color="blue" /> : <IconDownload size={14} />} rightSection={<IconChevronDown size={14} />} disabled={installing || !canWrite}>
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

        <Tabs defaultValue="overview" variant="pills" radius="md" keepMounted={false}>
          <Tabs.List mb="lg" className="scrollable-tabs-list">
            <Tabs.Tab value="overview" leftSection={<IconDashboard size={16} />}>Overview</Tabs.Tab>
            <Tabs.Tab value="explorer" leftSection={<IconSearch size={16} />}>Threat Explorer</Tabs.Tab>
            <Tabs.Tab value="incidents" leftSection={<IconAlertTriangle size={16} />}>Incidents</Tabs.Tab>
            <Tabs.Tab value="analytics" leftSection={<IconActivity size={16} />}>Analytics & Trends</Tabs.Tab>
            <Tabs.Tab value="advisory" leftSection={<IconBrain size={16} />}>AI Advisory</Tabs.Tab>
            <Tabs.Tab value="waf-rules" leftSection={<IconCode size={16} />}>WAF Rules</Tabs.Tab>
          </Tabs.List>

          <Tabs.Panel value="overview">
            <OverviewTab 
              metrics={metrics ?? null}
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
              metrics={metrics ?? null}
              trendData={trendData}
              countryData={countryData}
              threatTypeData={threatTypeData}
              totalThreats={totalThreats}
            />
          </Tabs.Panel>

          <Tabs.Panel value="advisory">
            <AIAdvisoryTab />
          </Tabs.Panel>

          <Tabs.Panel value="waf-rules">
            <WAFRulesTab />
          </Tabs.Panel>
        </Tabs>
      </Stack>

      <Modal
        opened={sudoOpened}
        onClose={() => {
          setSudoOpened(false);
          setSudoPassword("");
        }}
        title="Administrative Privileges Required"
        radius="md"
      >
        <Stack gap="md">
          <Text size="sm">
            This operation requires root privileges. Please provide your sudo password to proceed.
          </Text>
          <PasswordInput
            label="Sudo Password"
            placeholder="Your password"
            value={sudoPassword}
            onChange={(e) => setSudoPassword(e.currentTarget.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                handleSudoConfirm();
              }
            }}
          />
          <Group justify="flex-end">
            <Button variant="light" onClick={() => setSudoOpened(false)}>Cancel</Button>
            <Button onClick={handleSudoConfirm}>{pendingMode === 3 ? 'Uninstall' : 'Confirm'}</Button>
          </Group>
        </Stack>
      </Modal>
    </Container>
  );
}

