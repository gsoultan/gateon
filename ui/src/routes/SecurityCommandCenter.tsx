// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import React from 'react';
import { 
  Text,
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
  Drawer,
  SegmentedControl,
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
  IconBrain,
  IconAlertTriangle,
  IconCode,
  IconBan,
} from '@tabler/icons-react';
import { useGateonStatus, apiFetch, useMetricsSnapshot, installClamav, uninstallClamav } from '../hooks/useGateon';
import { notifications } from '@mantine/notifications';
import { Link } from '@tanstack/react-router';
import { usePermissions } from '../hooks/usePermissions';
import type { GlobalConfig, DeepScanStatus } from '../types/gateon';
import { format } from 'date-fns';

import { safeFormatDate } from '../utils/format';

import { OverviewTab } from '../components/SecurityCenter/OverviewTab';
import { ThreatExplorerTab } from '../components/SecurityCenter/ThreatExplorerTab';
import { IncidentsTab } from '../components/SecurityCenter/IncidentsTab';
import { AnomalyEngineTab } from '../components/SecurityCenter/AnomalyEngineTab';
import { AnalyticsTab } from '../components/SecurityCenter/AnalyticsTab';
import { AIAdvisoryTab } from '../components/SecurityCenter/AIAdvisoryTab';
import { WAFRulesTab } from '../components/SecurityCenter/WAFRulesTab';
// The archive reads files most visits never open, so it loads with its tab.
const ThreatArchiveTab = React.lazy(() => import('../components/SecurityCenter/ThreatArchiveTab'));
import { PageHeader } from "../components/layout";
import { useUrlFilters } from "../hooks/useUrlFilters";
import { getThreatColor } from '../utils/security';
import { resolveTrafficRangeBounds, DAY_MS } from '../utils/dashboard';
import type { TrafficRangePreset } from '../utils/dashboard';

const SECURITY_TABS = ["posture", "threats", "blocks", "rules"] as const;
const THREAT_VIEWS = ["live", "anomalies", "history", "trends", "archive"] as const;

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
  const { data: status, refetch: refetchStatus } = useGateonStatus();
  const [globalConfig, setGlobalConfig] = React.useState<GlobalConfig | null>(null);
  const [installing, setInstalling] = React.useState(false);
  const [uninstalling, setUninstalling] = React.useState(false);
  const [scanning, setScanning] = React.useState(false);
  const [scanStatus, setScanStatus] = React.useState<DeepScanStatus | null>(null);
  const pollIntervalRef = React.useRef<ReturnType<typeof setInterval> | null>(null);
  const [trendRange, setTrendRange] = React.useState<string>('last24h');
  // The tab, the threats view and the advisory panel live in the URL, so the
  // Overview's chips and the attention list can open the page at the right one.
  const [filters, setFilters] = useUrlFilters<{ tab: string; view: string; advisory: string }>();
  const tab = SECURITY_TABS.find((t) => t === filters.tab) ?? "posture";
  const threatView = THREAT_VIEWS.find((v) => v === filters.view) ?? "live";
  const advisoryOpen = filters.advisory === "1";
  const showTab = (next: string | null) => {
    const value = SECURITY_TABS.find((t) => t === next) ?? "posture";
    setFilters({ tab: value === "posture" ? undefined : value, view: undefined });
  };
  const [sudoOpened, setSudoOpened] = React.useState(false);
  const [pendingMode, setPendingMode] = React.useState<number | null>(null);
  const [sudoPassword, setSudoPassword] = React.useState("");
  // The header's "Uninstall ClamAV" used to call handleUninstall directly. In
  // local mode that at least stopped at the sudo prompt; in Docker mode (or
  // before /v1/global had loaded, when the mode is unknown) one click removed
  // the antivirus with no confirmation at all. /clamav has always asked first.
  const [confirmUninstallOpened, setConfirmUninstallOpened] = React.useState(false);

  // Reads scan state. Deliberately the GET endpoint, not the POST that starts a
  // scan: this used to poll RunDeepScan, which answers "is a scan running?" by
  // starting one when the answer is no. Opening this page launched a full
  // filesystem scan on any host with ClamAV installed.
  const pollScanStatus = async () => {
    try {
      const res = await apiFetch("/v1/security/clamav/scan-status");
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

  // Install and uninstall both return as soon as the work is queued, so the
  // response says nothing about whether ClamAV ended up installed. Nothing then
  // refetched /v1/status — the query has no interval — so the card kept offering
  // "Install Now" after a successful install until the user happened to hit the
  // shell's refresh. It read as a backend failure and it was a missing refetch.
  //
  // Poll until the status agrees with what was asked for, or until the deadline
  // passes so a genuinely failed install does not leave a timer running.
  const clamavPollRef = React.useRef<ReturnType<typeof setInterval> | null>(null);

  const stopClamavPoll = React.useCallback(() => {
    if (clamavPollRef.current) {
      clearInterval(clamavPollRef.current);
      clamavPollRef.current = null;
    }
  }, []);

  React.useEffect(() => stopClamavPoll, [stopClamavPoll]);

  const pollClamavUntil = React.useCallback((installed: boolean) => {
    stopClamavPoll();
    const deadline = Date.now() + 60_000;
    clamavPollRef.current = setInterval(async () => {
      const { data } = await refetchStatus();
      if (data?.clamavInstalled === installed || Date.now() > deadline) {
        stopClamavPoll();
      }
    }, 2000);
  }, [refetchStatus, stopClamavPoll]);

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
        // Installing persists the chosen mode server-side (ApiService.InstallClamav
        // writes waf.clamav.installation_mode), so the copy this component loaded
        // at mount is now stale. handleUninstall branches on that value to decide
        // whether to prompt for a sudo password, so a stale mode sent the uninstall
        // down the no-password path and the preflight then rejected it. Refresh so
        // the next action sees what was actually saved.
        void loadGlobalConfig();
        pollClamavUntil(true);
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
        pollClamavUntil(false);
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

  const loadGlobalConfig = React.useCallback(async () => {
    try {
      const r = await apiFetch("/v1/global");
      setGlobalConfig(r.ok ? await r.json() : null);
    } catch {
      // Leave the previous config in place; the card degrades to its
      // unconfigured state rather than throwing out of an effect.
    }
  }, []);

  React.useEffect(() => {
    void loadGlobalConfig();
  }, [loadGlobalConfig]);

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
    <Stack gap="xl">
        <PageHeader
          title="Security"
          description="What protects traffic right now, what was seen, what was done about it, and the rules behind it."
          actions={
            <Group gap="sm" wrap="wrap">
              <Button variant="light" leftSection={<IconBrain size={16} />} onClick={() => setFilters({ advisory: "1" })}>
                AI Advisory
              </Button>
              <Stack gap={2}>
                <Button
                  leftSection={scanning ? <Loader size={16} color="white" /> : <IconShieldCheck size={16} />}
                  onClick={handleDeepScan}
                  disabled={scanning || !status?.clamavInstalled || !canWrite}
                >
                  {scanning ? 'Scanning...' : 'Deep scan'}
                </Button>
                {scanStatus?.lastScan && !scanning && (
                  <Text size="10px" c="dimmed" ta="right" fw={500}>
                    Last scan: {safeFormatDate(scanStatus.lastScan, 'MMM d, HH:mm')}
                  </Text>
                )}
              </Stack>
              {status?.clamavInstalled && (
                <Button
                  variant="subtle"
                  color="red"
                  leftSection={uninstalling ? <Loader size={16} color="red" /> : <IconTrash size={16} />}
                  onClick={() => setConfirmUninstallOpened(true)}
                  disabled={uninstalling || !canWrite}
                >
                  Uninstall ClamAV
                </Button>
              )}
            </Group>
          }
        />

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

        <Tabs value={tab} onChange={showTab} keepMounted={false}>
          <Tabs.List mb="lg">
            <Tabs.Tab value="posture" leftSection={<IconShieldCheck size={16} />}>Posture</Tabs.Tab>
            <Tabs.Tab value="threats" leftSection={<IconAlertTriangle size={16} />}>Threats</Tabs.Tab>
            <Tabs.Tab value="blocks" leftSection={<IconBan size={16} />}>Blocks</Tabs.Tab>
            <Tabs.Tab value="rules" leftSection={<IconCode size={16} />}>Rules</Tabs.Tab>
          </Tabs.List>

          <Tabs.Panel value="posture">
            <OverviewTab 
              metrics={metrics ?? null}
              threatTypeData={threatTypeData}
              totalThreats={totalThreats}
            />
          </Tabs.Panel>

          <Tabs.Panel value="threats">
            <Stack gap="md">
              <Group justify="space-between" wrap="wrap">
                <SegmentedControl
                  value={threatView}
                  onChange={(v) => setFilters({ view: v === "live" ? undefined : v })}
                  data={[
                    { value: "live", label: "Live" },
                    { value: "anomalies", label: "Anomalies" },
                    { value: "history", label: "History" },
                    { value: "trends", label: "Trends" },
                    { value: "archive", label: "Archive" },
                  ]}
                  aria-label="Which threats to show"
                />
                {threatView === "trends" && (
                  <Select
                    aria-label="Trend range"
                    size="xs"
                    w={170}
                    data={TREND_RANGE_OPTIONS}
                    value={trendRange}
                    onChange={(value) => setTrendRange(value ?? 'last24h')}
                    allowDeselect={false}
                  />
                )}
              </Group>
              {threatView === "live" && <ThreatExplorerTab view="detected" />}
              {threatView === "anomalies" && <AnomalyEngineTab />}
              {threatView === "history" && <ThreatExplorerTab view="all" />}
              {threatView === "trends" && (
                <AnalyticsTab 
                  metrics={metrics ?? null}
                  trendData={trendData}
                  countryData={countryData}
                  threatTypeData={threatTypeData}
                  totalThreats={totalThreats}
                />
              )}
              {threatView === "archive" && (
                <React.Suspense fallback={<Loader m="xl" />}>
                  <ThreatArchiveTab />
                </React.Suspense>
              )}
            </Stack>
          </Tabs.Panel>

          <Tabs.Panel value="blocks">
            <Stack gap="xl">
              <ThreatExplorerTab view="mitigated" />
              <IncidentsTab />
            </Stack>
          </Tabs.Panel>

          <Tabs.Panel value="rules">
            <WAFRulesTab />
          </Tabs.Panel>
        </Tabs>

        <Drawer opened={advisoryOpen} onClose={() => setFilters({ advisory: undefined })} title="AI Advisory" position="right" size="xl" padding="lg">
          <AIAdvisoryTab />
        </Drawer>
      <Modal
        opened={confirmUninstallOpened}
        onClose={() => setConfirmUninstallOpened(false)}
        title="Uninstall ClamAV?"
        centered
        radius="md"
      >
        <Stack gap="md">
          <Text size="sm">
            This removes the ClamAV daemon from this host. Uploaded files stop being scanned for malware
            immediately, and any WAF rule relying on malware detection stops matching.
          </Text>
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setConfirmUninstallOpened(false)}>
              Cancel
            </Button>
            <Button
              color="red"
              onClick={() => {
                setConfirmUninstallOpened(false);
                void handleUninstall();
              }}
            >
              Uninstall ClamAV
            </Button>
          </Group>
        </Stack>
      </Modal>

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
    </Stack>
  );
}

