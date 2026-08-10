// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import React, { Suspense, lazy, useEffect, useMemo, useState } from "react";
import {
  ActionIcon,
  Alert,
  Anchor,
  Badge,
  Box,
  Center,
  Code,
  Group,
  Loader,
  Pagination,
  Paper,
  SimpleGrid,
  Stack,
  Tabs,
  Text,
  ThemeIcon,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  IconActivity,
  IconAlertTriangle,
  IconArrowRight,
  IconBug,
  IconCheck,
  IconCircleCheck,
  IconGlobe,
  IconInfoCircle,
  IconLock,
  IconRobot,
  IconShield,
  IconShieldExclamation,
  IconShieldLock,
  IconX,
} from "@tabler/icons-react";

import { applyRecommendation } from "../../hooks/api";
import { useDiagnostics } from "../../hooks/useDiagnostics";
import { usePermissions } from "../../hooks/usePermissions";
import type { Anomaly } from "../../types/gateon";
import { SecurityAnomalyModal } from "../SecurityAnomalyModal";
import TraceVisualizer from "../Diagnostics/TraceVisualizer";

// Leaflet lives in the heavy viz-vendor chunk, so the map is only pulled in when
// this tab is actually opened.
const AnomalyMap = lazy(() => import("../Diagnostics/AnomalyMap"));

const THREATS_PER_PAGE = 6;

/**
 * The live anomaly engine, previously the second half of the diagnostics page.
 *
 * It reads /v1/diagnostics rather than the persisted security_threats table, so
 * it is not a duplicate of the Threat Explorer — it is what the analysis engine
 * currently believes, with a recommendation attached to each finding. What was
 * duplicated is the *acting*: mitigating and applying fixes existed on two
 * pages, with two code paths and two sets of e2e tests, and three of those tests
 * were failing. Threats are dealt with here now, and the diagnostics page went
 * back to being about whether the gateway is healthy.
 */
export function AnomalyEngineTab() {
  const { canWrite } = usePermissions();
  const { data, refetch } = useDiagnostics();

  const [applying, setApplying] = useState<string | null>(null);
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [visualizerOpened, setVisualizerOpened] = useState(false);
  const [modalOpened, setModalOpened] = useState(false);
  const [selectedAnomaly, setSelectedAnomaly] = useState<Anomaly | null>(null);
  const [activePage, setActivePage] = useState(1);
  const [mitigatedPage, setMitigatedPage] = useState(1);

  const openVisualizer = (ip: string) => {
    if (!ip || ip === "-" || ip === "127.0.0.1") return;
    setSelectedIp(ip);
    setVisualizerOpened(true);
  };

  const onAnomalyClick = (anomaly: Anomaly) => {
    setSelectedAnomaly(anomaly);
    setModalOpened(true);
  };

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

  const activeThreats = useMemo(() => sortedAnomalies.filter((a) => !a.mitigated), [sortedAnomalies]);
  const mitigatedThreats = useMemo(() => sortedAnomalies.filter((a) => a.mitigated), [sortedAnomalies]);

  const activeTotalPages = Math.max(1, Math.ceil(activeThreats.length / THREATS_PER_PAGE));
  const mitigatedTotalPages = Math.max(1, Math.ceil(mitigatedThreats.length / THREATS_PER_PAGE));

  // Clamp the current page when the underlying list shrinks, or a refresh that
  // mitigates the last threat on page 3 leaves the operator staring at nothing.
  useEffect(() => setActivePage((p) => Math.min(p, activeTotalPages)), [activeTotalPages]);
  useEffect(() => setMitigatedPage((p) => Math.min(p, mitigatedTotalPages)), [mitigatedTotalPages]);

  const pagedActive = useMemo(
    () => activeThreats.slice((activePage - 1) * THREATS_PER_PAGE, activePage * THREATS_PER_PAGE),
    [activeThreats, activePage],
  );
  const pagedMitigated = useMemo(
    () => mitigatedThreats.slice((mitigatedPage - 1) * THREATS_PER_PAGE, mitigatedPage * THREATS_PER_PAGE),
    [mitigatedThreats, mitigatedPage],
  );

  const activeStats = useMemo(() => severityCounts(activeThreats), [activeThreats]);
  const mitigatedStats = useMemo(() => severityCounts(mitigatedThreats), [mitigatedThreats]);

  const handleApply = async (anomaly: Anomaly) => {
    const key = `${anomaly.type}-${anomaly.source}`;
    try {
      setApplying(key);
      const res = await applyRecommendation(anomaly.type, anomaly.source, anomaly.id);
      notifications.show({
        title: res.success ? "Recommendation applied" : "Could not apply the fix",
        message: res.message,
        color: res.success ? "teal" : "red",
        icon: res.success ? <IconCheck size={18} /> : <IconX size={18} />,
      });
      if (res.success) setTimeout(() => void refetch(), 1000);
    } catch {
      notifications.show({
        title: "Could not apply the fix",
        message: "The gateway did not accept the change. It is still in place.",
        color: "red",
        icon: <IconX size={18} />,
      });
    } finally {
      setApplying(null);
    }
  };

  const renderList = (
    list: Anomaly[],
    paged: Anomaly[],
    stats: ReturnType<typeof severityCounts>,
    page: number,
    setPage: (n: number) => void,
    totalPages: number,
    empty: { icon: React.ReactNode; title: string; hint: string; color: string },
    paginationColor: string,
  ) => (
    <Stack gap="md">
      <SimpleGrid cols={{ base: 2, sm: 4 }} spacing="xs">
        <SeverityStatCard label="Critical" count={stats.critical} color="red" icon={<IconShieldExclamation size={14} />} />
        <SeverityStatCard label="High" count={stats.high} color="orange" icon={<IconShield size={14} />} />
        <SeverityStatCard label="Medium" count={stats.medium} color="yellow" icon={<IconInfoCircle size={14} />} />
        <SeverityStatCard label="Low" count={stats.low} color="blue" icon={<IconInfoCircle size={14} />} />
      </SimpleGrid>

      {list.length > 0 ? (
        <>
          <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
            {paged.map((a) => (
              <AnomalyCard
                key={`${a.type}-${a.source}-${a.timestamp}`}
                anomaly={a}
                onApply={() => handleApply(a)}
                applying={applying === `${a.type}-${a.source}`}
                onTrace={openVisualizer}
                onClick={() => onAnomalyClick(a)}
                canWrite={canWrite}
              />
            ))}
          </SimpleGrid>
          {totalPages > 1 && (
            <Center mt="xs">
              <Pagination total={totalPages} value={page} onChange={setPage} color={paginationColor} size="sm" radius="md" />
            </Center>
          )}
        </>
      ) : (
        <Paper p="xl" withBorder radius="lg" style={{ borderStyle: "dashed" }}>
          <Stack align="center" gap="xs">
            {empty.icon}
            <Text fw={700} c={empty.color}>
              {empty.title}
            </Text>
            <Text size="xs" c="dimmed">
              {empty.hint}
            </Text>
          </Stack>
        </Paper>
      )}
    </Stack>
  );

  return (
    <Stack gap="md" mt="md">
      <Group justify="space-between">
        <Group gap="xs">
          <ThemeIcon variant="light" color="indigo" size="lg" radius="md">
            <IconRobot size={20} />
          </ThemeIcon>
          <div>
            <Title order={4} fw={800}>
              Anomaly Intelligence Engine
            </Title>
            <Text size="xs" c="dimmed">
              What the analysis engine currently believes about live traffic, with a recommended action
              for each finding.
            </Text>
          </div>
        </Group>
        <Badge variant="dot" color="indigo" size="lg">
          Autonomous protection
        </Badge>
      </Group>

      <Suspense fallback={<Loader size="sm" />}>
        <AnomalyMap anomalies={sortedAnomalies} onTrace={openVisualizer} />
      </Suspense>

      <Tabs defaultValue="active" variant="pills" radius="md">
        <Tabs.List mb="md" className="scrollable-tabs-list">
          <Tabs.Tab value="active" leftSection={<IconAlertTriangle size={14} />} color="red">
            Active threats ({activeThreats.length})
          </Tabs.Tab>
          <Tabs.Tab value="mitigated" leftSection={<IconCircleCheck size={14} />} color="teal">
            Mitigated ({mitigatedThreats.length})
          </Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="active">
          {renderList(
            activeThreats,
            pagedActive,
            activeStats,
            activePage,
            setActivePage,
            activeTotalPages,
            {
              icon: <IconCircleCheck size={40} color="var(--mantine-color-teal-4)" />,
              title: "No active threats",
              hint: "The engine has not flagged anything in the traffic it has seen.",
              color: "teal",
            },
            "red",
          )}
        </Tabs.Panel>

        <Tabs.Panel value="mitigated">
          {renderList(
            mitigatedThreats,
            pagedMitigated,
            mitigatedStats,
            mitigatedPage,
            setMitigatedPage,
            mitigatedTotalPages,
            {
              icon: <IconInfoCircle size={40} color="var(--mantine-color-gray-4)" />,
              title: "Nothing mitigated yet",
              hint: "Threats you act on appear here.",
              color: "dimmed",
            },
            "teal",
          )}
        </Tabs.Panel>
      </Tabs>

      <SecurityAnomalyModal opened={modalOpened} onClose={() => setModalOpened(false)} anomaly={selectedAnomaly} />
      <TraceVisualizer opened={visualizerOpened} onClose={() => setVisualizerOpened(false)} targetIp={selectedIp || ""} />
    </Stack>
  );
}

function severityCounts(threats: Anomaly[]) {
  const count = (sev: string) => threats.filter((t) => t.severity.toLowerCase() === sev).length;
  return { critical: count("critical"), high: count("high"), medium: count("medium"), low: count("low") };
}

const SeverityStatCard: React.FC<{ label: string; count: number; color: string; icon: React.ReactNode }> = ({
  label,
  count,
  color,
  icon,
}) => (
  <Paper withBorder p="xs" radius="md" style={{ flex: 1 }}>
    <Group gap="xs" wrap="nowrap">
      <ThemeIcon color={color} variant="light" size="sm">
        {icon}
      </ThemeIcon>
      <Box>
        <Text size="xs" c="dimmed" fw={700} style={{ textTransform: "uppercase", fontSize: "9px", letterSpacing: 0.5 }}>
          {label}
        </Text>
        <Text fw={800} size="sm" style={{ lineHeight: 1 }}>
          {count}
        </Text>
      </Box>
    </Group>
  </Paper>
);

const AnomalyCard: React.FC<{
  anomaly: Anomaly;
  onApply: () => void;
  applying: boolean;
  onTrace: (ip: string) => void;
  onClick?: () => void;
  canWrite?: boolean;
}> = ({ anomaly, onApply, applying, onTrace, onClick, canWrite }) => {
  const severityColor = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical":
        return "red";
      case "high":
        return "orange";
      case "medium":
        return "yellow";
      default:
        return "blue";
    }
  };

  const icon = (type: string) => {
    const t = type.toLowerCase();
    if (t.includes("attack") || t.includes("hacker") || t.includes("violation") || t.includes("waf") || t.includes("sqli") || t.includes("xss"))
      return <IconShieldLock size={20} />;
    if (t.includes("brute")) return <IconLock size={20} />;
    if (t.includes("scan") || t.includes("security") || t.includes("path")) return <IconBug size={20} />;
    if (t.includes("geofence")) return <IconGlobe size={20} />;
    if (t.includes("integrity")) return <IconShield size={20} />;
    if (t.includes("honeypot")) return <IconAlertTriangle size={20} />;
    return <IconActivity size={20} />;
  };

  return (
    <Paper
      withBorder
      p="md"
      radius="lg"
      shadow="sm"
      onClick={onClick}
      data-testid="anomaly-card"
      style={{
        borderLeft: `4px solid var(--mantine-color-${severityColor(anomaly.severity)}-6)`,
        cursor: onClick ? "pointer" : "default",
        transition: "transform 0.2s ease, box-shadow 0.2s ease",
      }}
      className={onClick ? "hover-elevated" : ""}
    >
      <Stack gap="xs">
        <Group justify="space-between">
          <Group gap="sm">
            <ThemeIcon variant="light" color={severityColor(anomaly.severity)} size="lg" radius="md">
              {icon(anomaly.type)}
            </ThemeIcon>
            <Stack gap={0}>
              <Group gap={4}>
                <Text fw={800} size="sm" style={{ textTransform: "uppercase", letterSpacing: 0.5 }}>
                  {(anomaly.type || "unknown").replace(/_/g, " ")}
                </Text>
                {anomaly.category && (
                  <Badge variant="light" color="gray" size="xs">
                    {anomaly.category}
                  </Badge>
                )}
              </Group>
              <Text size="xs" c="dimmed">
                {(() => {
                  const date = new Date(anomaly.timestamp);
                  return isNaN(date.getTime()) ? "N/A" : date.toLocaleString();
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
            <Tooltip label="Trace IP route">
              <ActionIcon variant="light" color="blue" size="sm" onClick={() => onTrace(anomaly.source)}>
                <IconGlobe size={14} />
              </ActionIcon>
            </Tooltip>
            <Badge color={severityColor(anomaly.severity)} variant="filled" size="xs">
              {anomaly.severity}
            </Badge>
          </Group>
        </Group>

        <Text size="sm" fw={500}>
          {anomaly.description}
        </Text>
        <Group gap={4}>
          <Text size="xs" c="dimmed">
            Source:
          </Text>
          <Code color="blue.0" c="blue.8" style={{ cursor: "pointer" }} onClick={() => onTrace(anomaly.source)}>
            {anomaly.source}
          </Code>
        </Group>

        <Alert variant="light" color="indigo" radius="md" p="sm" icon={<IconRobot size={18} />}>
          <Stack gap="xs">
            <Text size="xs" fw={700}>
              System recommendation:
            </Text>
            <Text size="xs">{anomaly.recommendation}</Text>
            {!anomaly.mitigated && canWrite && (
              <Group justify="flex-end">
                <Anchor
                  component="button"
                  size="xs"
                  fw={800}
                  onClick={onApply}
                  style={{ display: "flex", alignItems: "center", gap: 4 }}
                >
                  {applying && <Loader size={10} mr={4} />}
                  Apply automatic fix <IconArrowRight size={12} />
                </Anchor>
              </Group>
            )}
          </Stack>
        </Alert>
      </Stack>
    </Paper>
  );
};
