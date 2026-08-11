// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Card,
  Center,
  Group,
  Loader,
  Menu,
  Modal,
  SimpleGrid,
  Stack,
  Text,
  ThemeIcon,
  Title,
} from "@mantine/core";
import {
  IconAdjustments,
  IconAlertTriangle,
  IconBox,
  IconChevronDown,
  IconClock,
  IconDownload,
  IconInfoCircle,
  IconRefresh,
  IconSettings,
  IconShieldCheck,
  IconTrash,
  IconVirus,
} from "@tabler/icons-react";
import { Link } from "@tanstack/react-router";

import { apiFetch } from "../hooks/useGateon";
import { useGateonStatus } from "../hooks/useGateonStatus";
import { usePermissions } from "../hooks/usePermissions";
import { safeFormatDate } from "../utils/format";

type ScanStatus = {
  isRunning?: boolean;
  lastScan?: string;
  lastError?: string;
  lastResult?: string;
};

/**
 * Poll interval while a scan is running.
 *
 * Nothing polls when a scan is not running: the status is only capable of
 * changing while one is in progress, or in response to a button on this page,
 * and both of those already refresh it. gateon is sized for a 2-core host, so
 * an idle dashboard tab should cost nothing.
 */
const SCAN_POLL_MS = 5000;

export default function ClamAVPage() {
  const { data: status, isLoading: statusLoading, error: statusError } = useGateonStatus();
  const canWrite = !usePermissions().isViewer;

  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"scan" | "install" | "uninstall" | null>(null);
  const [confirmUninstall, setConfirmUninstall] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const installed = !!status?.clamavInstalled;

  // Reads state. This is the GET endpoint on purpose — the POST it replaced
  // starts a scan when none is running, so polling it turned opening a page
  // into a full filesystem scan.
  const refresh = useCallback(async () => {
    try {
      const res = await apiFetch("/v1/security/clamav/scan-status");
      const data = await res.json();
      if (data?.success) {
        setScan(data.status ?? null);
        setLoadError(null);
      } else {
        setLoadError(data?.message || "ClamAV status is unavailable.");
      }
    } catch {
      setLoadError("Could not reach the gateway to read ClamAV status.");
    }
  }, []);

  useEffect(() => {
    if (installed) void refresh();
  }, [installed, refresh]);

  useEffect(() => {
    if (scan?.isRunning) {
      pollRef.current = setInterval(() => void refresh(), SCAN_POLL_MS);
    } else if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [scan?.isRunning, refresh]);

  const act = async (kind: "scan" | "install" | "uninstall", path: string, body?: unknown) => {
    setBusy(kind);
    setLoadError(null);
    try {
      const res = await apiFetch(path, {
        method: "POST",
        headers: body ? { "Content-Type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      });
      const data = await res.json();
      if (!res.ok || data?.success === false) {
        setLoadError(data?.message || "The gateway refused the request.");
      }
      await refresh();
    } catch {
      setLoadError("Could not reach the gateway.");
    } finally {
      setBusy(null);
    }
  };

  if (statusLoading) {
    return (
      <Center py="xl">
        <Loader />
      </Center>
    );
  }

  if (statusError) {
    return (
      <Alert color="red" icon={<IconAlertTriangle size={16} />} title="Gateway status unavailable" radius="md">
        ClamAV state could not be read because the gateway did not answer. The scanner itself may still
        be running.
      </Alert>
    );
  }

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="flex-start">
        <div>
          <Group gap="sm">
            <ThemeIcon variant="light" color={installed ? "teal" : "gray"} size="lg" radius="md">
              <IconVirus size={20} />
            </ThemeIcon>
            <Title order={2} fw={800} style={{ letterSpacing: -0.5 }}>
              Antivirus
            </Title>
            <Badge color={installed ? "teal" : "gray"} variant="light">
              {installed ? "Installed" : "Not installed"}
            </Badge>
          </Group>
          <Text c="dimmed" size="sm" fw={500} mt={4}>
            ClamAV scans uploaded files and the gateway's own filesystem for malware.
          </Text>
        </div>

        {installed && canWrite && (
          <Group gap="xs">
            <Button
              leftSection={scan?.isRunning ? <Loader size={16} color="white" /> : <IconShieldCheck size={16} />}
              onClick={() => act("scan", "/v1/security/clamav/scan")}
              disabled={!!busy || scan?.isRunning}
            >
              {scan?.isRunning ? "Scanning…" : "Run deep scan"}
            </Button>
            <Button variant="subtle" leftSection={<IconRefresh size={16} />} onClick={() => void refresh()}>
              Refresh
            </Button>
            <Button
              variant="subtle"
              color="red"
              leftSection={<IconTrash size={16} />}
              onClick={() => setConfirmUninstall(true)}
              disabled={!!busy}
            >
              Uninstall
            </Button>
          </Group>
        )}
      </Group>

      {loadError && (
        <Alert color="red" icon={<IconAlertTriangle size={16} />} radius="md" withCloseButton onClose={() => setLoadError(null)}>
          {loadError}
        </Alert>
      )}

      {!installed ? (
        <Card withBorder radius="lg" padding="xl">
          <Center>
            <Stack align="center" gap="sm" maw={460}>
              <ThemeIcon variant="light" color="gray" size={48} radius="xl">
                <IconVirus size={26} />
              </ThemeIcon>
              <Title order={4}>ClamAV is not installed</Title>
              <Text c="dimmed" size="sm" ta="center">
                File upload scanning and malware detection are inactive until it is. Local installs run
                the daemon on this host; Docker runs it in a container alongside the gateway.
              </Text>
              {canWrite ? (
                <Menu shadow="md" width={220} position="bottom">
                  <Menu.Target>
                    <Button
                      leftSection={busy === "install" ? <Loader size={14} /> : <IconDownload size={16} />}
                      rightSection={<IconChevronDown size={14} />}
                      disabled={!!busy}
                      mt="xs"
                    >
                      Install ClamAV
                    </Button>
                  </Menu.Target>
                  <Menu.Dropdown>
                    <Menu.Label>Installation mode</Menu.Label>
                    <Menu.Item
                      leftSection={<IconAdjustments size={14} />}
                      onClick={() => act("install", "/v1/security/clamav/install", { mode: 1 })}
                    >
                      Local
                    </Menu.Item>
                    <Menu.Item
                      leftSection={<IconBox size={14} />}
                      onClick={() => act("install", "/v1/security/clamav/install", { mode: 2 })}
                    >
                      Docker
                    </Menu.Item>
                  </Menu.Dropdown>
                </Menu>
              ) : (
                <Text size="xs" c="dimmed">
                  Installing requires an operator or admin account.
                </Text>
              )}
            </Stack>
          </Center>
        </Card>
      ) : (
        <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="md">
          <StatCard
            icon={<IconClock size={16} />}
            color="blue"
            label="Last scan"
            value={scan?.lastScan ? safeFormatDate(scan.lastScan, "MMM d, HH:mm") : "Never"}
          />
          <StatCard
            icon={<IconShieldCheck size={16} />}
            color={scan?.isRunning ? "orange" : "teal"}
            label="State"
            value={scan?.isRunning ? "Scan in progress" : "Idle"}
          />
          <StatCard
            icon={<IconInfoCircle size={16} />}
            color={scan?.lastError ? "red" : "gray"}
            label="Last result"
            value={scan?.lastError || scan?.lastResult || "No findings recorded"}
          />
        </SimpleGrid>
      )}

      {installed && (
        <Card withBorder radius="lg" padding="lg">
          <Group justify="space-between" align="center">
            <div>
              <Text fw={700} size="sm">
                Scan schedules and daemon address
              </Text>
              <Text c="dimmed" size="xs">
                Full-scan cron, database updates and the clamd address are configured with the rest of
                the gateway.
              </Text>
            </div>
            <Button variant="light" leftSection={<IconSettings size={16} />} component={Link} to="/settings">
              Open settings
            </Button>
          </Group>
        </Card>
      )}

      <Modal
        opened={confirmUninstall}
        onClose={() => setConfirmUninstall(false)}
        title="Uninstall ClamAV?"
        centered
      >
        <Stack gap="md">
          <Text size="sm">
            This removes the ClamAV daemon from this host. Uploaded files stop being scanned for malware
            immediately, and any WAF rule relying on malware detection stops matching.
          </Text>
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setConfirmUninstall(false)}>
              Cancel
            </Button>
            <Button
              color="red"
              loading={busy === "uninstall"}
              onClick={() => {
                setConfirmUninstall(false);
                void act("uninstall", "/v1/security/clamav/uninstall");
              }}
            >
              Uninstall ClamAV
            </Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  );
}

function StatCard({
  icon,
  color,
  label,
  value,
}: {
  icon: React.ReactNode;
  color: string;
  label: string;
  value: string;
}) {
  return (
    <Card withBorder radius="lg" padding="md">
      <Group gap="xs" mb={6}>
        <ThemeIcon variant="light" color={color} size="sm" radius="sm">
          {icon}
        </ThemeIcon>
        <Text size="xs" c="dimmed" fw={700} tt="uppercase">
          {label}
        </Text>
      </Group>
      <Text fw={700} size="sm" style={{ wordBreak: "break-word" }}>
        {value}
      </Text>
    </Card>
  );
}
