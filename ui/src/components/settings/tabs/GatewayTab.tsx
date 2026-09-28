// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Stack } from "@mantine/core";
import { PresetsCard } from "../PresetsCard";
import { GatewayConfigCard } from "../gateway/GatewayConfigCard";
import { PerformanceEnvCard } from "../gateway/PerformanceEnvCard";
import { TraceArchiveSettingsCard } from "../../Traces/TraceArchiveSettingsCard";
import type { SettingsTabProps } from "./settingsState";

// Server-wide settings: TLS, Redis, transport, telemetry, the management API,
// logging and retention, and the presets that fill them.
export default function GatewayTab({ settings }: SettingsTabProps) {
  const { config, setConfig, formDisabled } = settings;
  return (
    <Stack gap="xl">
      <PresetsCard disabled={formDisabled} onApply={settings.applyPreset} />

      <GatewayConfigCard
        config={config}
        onChange={setConfig}
        disabled={formDisabled}
        canEdit={settings.canEditGlobal}
        saving={settings.saving}
        onSave={settings.saveGatewayConfig}
      />

      <PerformanceEnvCard />

      <TraceArchiveSettingsCard config={config} onChange={setConfig} disabled={formDisabled} />
    </Stack>
  );
}
