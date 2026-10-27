// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useMemo } from "react";
import { Card, Group, SegmentedControl, SimpleGrid, Skeleton, Stack, Text, Title } from "@mantine/core";
import { Link } from "@tanstack/react-router";
import { linkSearch } from "../layout/createLink";
import { useMetricsSnapshot } from "../../hooks/useMetricsSnapshot";
import { useRateHistory } from "../../hooks/useRateHistory";
import { StatTile } from "../status";
import { TrafficChart } from "./TrafficChart";
import { TRAFFIC_RANGES, trafficSeries, type TrafficRange } from "./trafficSeries";

interface TrafficNowProps {
  range: TrafficRange;
  onRangeChange: (range: TrafficRange) => void;
}

const RANGE_LABELS: Record<TrafficRange, string> = { "1h": "1h", "24h": "24h", "7d": "7d" };

const rate = (v: number | undefined) => (v === undefined ? "–" : v >= 100 ? Math.round(v).toLocaleString() : v.toFixed(1));
const ms = (v: number | undefined) => (v === undefined ? "–" : v >= 1000 ? `${(v / 1000).toFixed(2)} s` : `${Math.round(v)} ms`);
const clock = (ts: number) => new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
const day = (ts: number) => new Date(ts).toLocaleDateString([], { month: "short", day: "numeric", hour: "2-digit" });

/** Is traffic normal: req/s, errors/s and p99 now, and the shape of the chosen range. */
export function TrafficNow({ range, onRangeChange }: TrafficNowProps) {
  const { samples, isLoading } = useRateHistory();
  const { data: snapshot } = useMetricsSnapshot();
  const series = useMemo(() => trafficSeries(range, samples, snapshot?.trafficHistory), [range, samples, snapshot?.trafficHistory]);
  const latest = samples[samples.length - 1];
  const golden = snapshot?.goldenSignals;

  return (
    <Card withBorder radius="md" padding="lg">
      <Stack gap="md">
        <Group justify="space-between" align="center" wrap="wrap">
          <Title order={4}>Traffic now</Title>
          <Group gap="sm">
            <SegmentedControl
              size="xs"
              value={range}
              onChange={(v) => onRangeChange(v as TrafficRange)}
              data={TRAFFIC_RANGES.map((r) => ({ value: r, label: RANGE_LABELS[r] }))}
              aria-label="Traffic range"
            />
            <Text size="xs" component={Link} to="/metrics-dashboard" search={linkSearch({ tab: "traffic" })} c="dimmed">
              Breakdown
            </Text>
          </Group>
        </Group>
        <SimpleGrid cols={{ base: 1, xs: 3 }} spacing="sm">
          <StatTile label="Requests / s" value={rate(latest?.requestsPerSecond)} hint={latest ? "Since the last poll" : "Waiting for a second poll"} />
          <StatTile label="Errors / s" value={rate(latest?.errorsPerSecond)} hint="5xx answers" />
          <StatTile label="p99 latency" value={ms(golden?.p99LatencyMs)} hint="Across every route" />
        </SimpleGrid>
        {isLoading ? (
          <Skeleton height={180} radius="md" />
        ) : (
          <TrafficChart
            requests={series.requests}
            errors={series.errors}
            formatValue={(v) => rate(v)}
            formatTime={range === "1h" ? clock : day}
          />
        )}
        {series.note && (
          <Text size="xs" c="dimmed">
            {series.note}
          </Text>
        )}
      </Stack>
    </Card>
  );
}
