// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Group, Paper, SimpleGrid, Stack, Text } from "@mantine/core";
import { Link } from "@tanstack/react-router";
import { linkSearch } from "../layout/createLink";
import { useAggStats } from "../../hooks/useAggStats";
import { useGateonStatus } from "../../hooks/useGateonStatus";
import { useMetricsSnapshot } from "../../hooks/useMetricsSnapshot";
import { useSecurityPosture } from "../../hooks/useSecurityPosture";
import { StatusChip, ratioState, wafModeState, type StatusState } from "../status";
import { CERT_WARN_DAYS } from "./attention";

interface HealthItem {
  key: string;
  title: string;
  state: StatusState;
  label: string;
  detail: string;
  to: string;
  search?: Record<string, string>;
}

function certificateItem(certs: Array<{ daysRemaining: number }> | null | undefined): Pick<HealthItem, "state" | "label" | "detail"> {
  if (certs === undefined) return { state: "unknown", label: "Unknown", detail: "Waiting for metrics" };
  if (!certs || certs.length === 0) return { state: "off", label: "None", detail: "No certificate is served" };
  const soonest = Math.min(...certs.map((c) => c.daysRemaining));
  if (soonest <= 0) return { state: "down", label: "Expired", detail: "A certificate has expired" };
  if (soonest < CERT_WARN_DAYS) return { state: "degraded", label: `${soonest}d`, detail: `Soonest expiry in ${soonest} days` };
  return { state: "up", label: "Up", detail: `${certs.length} valid, soonest expiry in ${soonest} days` };
}

function HealthCard({ item }: { item: HealthItem }) {
  return (
    <Paper
      withBorder
      radius="md"
      p="md"
      component={Link}
      to={item.to}
      search={linkSearch(item.search)}
      style={{ textDecoration: "none", color: "inherit" }}
      aria-label={`${item.title}: ${item.label}`}
    >
      <Stack gap={6}>
        <Group justify="space-between" wrap="nowrap">
          <Text size="sm" fw={600}>
            {item.title}
          </Text>
          <StatusChip state={item.state} label={item.label} />
        </Group>
        <Text size="xs" c="dimmed" lineClamp={1}>
          {item.detail}
        </Text>
      </Stack>
    </Paper>
  );
}

/**
 * Five answers to "is the gateway healthy", each a link to where the answer
 * comes from. A value nobody has yet is Unknown, never a reassuring zero.
 */
export function HealthStrip() {
  const status = useGateonStatus();
  const { data: agg } = useAggStats();
  const { data: snapshot } = useMetricsSnapshot();
  const { data: posture } = useSecurityPosture();

  const gateway: HealthItem = {
    key: "gateway",
    title: "Gateway",
    ...(status.isError
      ? { state: "down" as const, label: "Down", detail: "The management API does not answer" }
      : status.data
        ? { state: "up" as const, label: "Up", detail: `Version ${status.data.version}, ${status.data.routesCount} routes` }
        : { state: "unknown" as const, label: "Unknown", detail: "Waiting for the gateway" }),
    to: "/diagnostics",
  };
  const backends = ratioState(agg?.healthyTargets, agg?.totalTargets);
  const waf = wafModeState(posture ? (posture.waf.enabled ? posture.waf.mode : "off") : undefined);
  const blocks = snapshot?.security?.mitigatedToday;

  const items: HealthItem[] = [
    gateway,
    {
      key: "backends",
      title: "Backends",
      ...backends,
      detail: agg ? `${agg.healthyTargets} of ${agg.totalTargets} healthy${agg.openCircuits ? `, ${agg.openCircuits} circuit open` : ""}` : "Waiting for stats",
      to: "/services",
    },
    { key: "certificates", title: "Certificates", ...certificateItem(snapshot ? snapshot.tlsCertificates : undefined), to: "/tls" },
    {
      key: "waf",
      title: "WAF",
      ...waf,
      detail: posture ? `${posture.waf.routes.enforcing} of ${posture.waf.routes.total} routes enforcing` : "Waiting for posture",
      to: "/security",
    },
    {
      key: "blocks",
      title: "Blocks today",
      state: blocks === undefined ? "unknown" : blocks > 0 ? "up" : "off",
      label: blocks === undefined ? "Unknown" : blocks.toLocaleString(),
      detail: blocks === undefined ? "Waiting for metrics" : blocks > 0 ? "Requests refused since midnight" : "Nothing refused since midnight",
      to: "/security",
      search: { tab: "blocks" },
    },
  ];

  return (
    <SimpleGrid cols={{ base: 1, xs: 2, md: 5 }} spacing="sm">
      {items.map((item) => (
        <HealthCard key={item.key} item={item} />
      ))}
    </SimpleGrid>
  );
}
