// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Stack } from "@mantine/core";
import { AISettingsCard } from "../AISettingsCard";
import { AlertingSettingsCard } from "../AlertingSettingsCard";
import { SettingsEntry } from "../AppliesChip";
import { OpenTelemetrySection } from "../gateway/OpenTelemetrySection";
import { RedisSection } from "../gateway/RedisSection";
import { SectionCard } from "./SectionCard";
import type { SettingsTabProps } from "./settingsState";

// Everything the gateway talks to that is not a backend: Redis for shared
// state, OpenTelemetry for traces, the alert destinations and the AI provider
// behind the advisory.
export default function IntegrationsTab({ settings }: SettingsTabProps) {
  const { config, setConfig, formDisabled } = settings;
  return (
    <Stack gap="xl">
      <SettingsEntry id="redis" applies="restart">
        <SectionCard title="Redis" description="Shared state between gateways: rate limits, sessions and caches.">
          <RedisSection redis={config.redis || { enabled: false }} onChange={(redis) => setConfig({ ...config, redis })} disabled={formDisabled} />
        </SectionCard>
      </SettingsEntry>

      <SettingsEntry id="otel" applies="restart">
        <SectionCard title="OpenTelemetry" description="Where request traces are exported.">
          <OpenTelemetrySection otel={config.otel || { enabled: false }} onChange={(otel) => setConfig({ ...config, otel })} disabled={formDisabled} />
        </SectionCard>
      </SettingsEntry>

      <SettingsEntry id="alerting" applies="now">
        <AlertingSettingsCard config={config} onChange={setConfig} disabled={formDisabled} />
      </SettingsEntry>

      <SettingsEntry id="ai" applies="now">
        <AISettingsCard config={config} onChange={setConfig} disabled={formDisabled} />
      </SettingsEntry>
    </Stack>
  );
}
