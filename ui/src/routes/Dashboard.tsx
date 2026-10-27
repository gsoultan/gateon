// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { lazy, Suspense } from "react";
import { Grid, Skeleton, Stack, Tabs } from "@mantine/core";
import { IconLayoutDashboard, IconSitemap } from "@tabler/icons-react";
import { PageHeader } from "../components/layout";
import { AttentionList } from "../components/Overview/AttentionList";
import { HealthStrip } from "../components/Overview/HealthStrip";
import { ResourcesCard } from "../components/Overview/ResourcesCard";
import { TrafficNow } from "../components/Overview/TrafficNow";
import { asTrafficRange } from "../components/Overview/trafficSeries";
import { useUrlFilters } from "../hooks/useUrlFilters";

const MapTab = lazy(() => import("../components/Overview/MapTab"));

const TABS = ["summary", "map"] as const;
type OverviewTab = (typeof TABS)[number];
const asTab = (v: string | undefined): OverviewTab => TABS.find((t) => t === v) ?? "summary";

/**
 * The home page answers three questions in one screen: is the gateway
 * healthy, is traffic normal, and what needs attention. The breakdown tables
 * that used to fill it are on Metrics › Traffic; the quick actions are the
 * sidebar; the setup steps are rows in Needs attention until they are done.
 */
export default function Dashboard() {
  const [filters, setFilters] = useUrlFilters<{ tab: string; range: string }>();
  const tab = asTab(filters.tab);
  const range = asTrafficRange(filters.range);

  return (
    <Stack gap="xl">
      <PageHeader title="Overview" description="Is the gateway healthy, is traffic normal, and what needs attention." />
      <Tabs value={tab} onChange={(v) => setFilters({ tab: asTab(v ?? undefined) === "summary" ? undefined : "map" })} keepMounted={false}>
        <Tabs.List>
          <Tabs.Tab value="summary" leftSection={<IconLayoutDashboard size={16} />}>
            Summary
          </Tabs.Tab>
          <Tabs.Tab value="map" leftSection={<IconSitemap size={16} />}>
            Map
          </Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="summary" pt="xl">
          <Stack gap="xl">
            <HealthStrip />
            <Grid gap="xl">
              <Grid.Col span={{ base: 12, lg: 8 }}>
                <TrafficNow range={range} onRangeChange={(r) => setFilters({ range: r === "1h" ? undefined : r })} />
              </Grid.Col>
              <Grid.Col span={{ base: 12, lg: 4 }}>
                <ResourcesCard />
              </Grid.Col>
            </Grid>
            <AttentionList />
          </Stack>
        </Tabs.Panel>
        <Tabs.Panel value="map" pt="xl">
          <Suspense fallback={<Skeleton height={480} radius="md" />}>
            <MapTab />
          </Suspense>
        </Tabs.Panel>
      </Tabs>
    </Stack>
  );
}
