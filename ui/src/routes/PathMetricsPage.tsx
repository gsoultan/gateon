// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Suspense, lazy } from "react";
import { Stack, Text } from "@mantine/core";
import { PageHeader } from "../components/layout";

const PathStatsTable = lazy(() =>
  import("../components/PathStatsTable").then((m) => ({
    default: m.PathStatsTable,
  })),
);

const FALLBACK = <Text>Loading path metrics...</Text>;

export default function PathMetricsPage() {
  return (
    <Stack gap="lg">
      <PageHeader
        title="Path Metrics"
        description="Detailed response time and request count statistics per host and path."
      />

      <Suspense fallback={FALLBACK}>
        <PathStatsTable />
      </Suspense>
    </Stack>
  );
}
