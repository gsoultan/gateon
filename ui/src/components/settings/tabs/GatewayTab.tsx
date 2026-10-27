// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Stack } from "@mantine/core";
import { SettingsEntry } from "../AppliesChip";
import { GatewayConfigCard } from "../gateway/GatewayConfigCard";
import { PerformanceEnvCard } from "../gateway/PerformanceEnvCard";
import { PresetsCard } from "../PresetsCard";
import type { SettingsTabProps } from "./settingsState";

// TLS, transports, the management API and sign-in; the presets that set
// several of them at once; and the environment the process was started with.
export default function GatewayTab({ settings }: SettingsTabProps) {
  const { config, setConfig, formDisabled } = settings;
  return (
    <Stack gap="xl">
      <SettingsEntry id="presets" applies="now">
        <PresetsCard config={config} disabled={formDisabled} onApply={settings.applyPreset} />
      </SettingsEntry>

      <SettingsEntry id="gateway" applies="connections">
        <GatewayConfigCard config={config} onChange={setConfig} disabled={formDisabled} />
      </SettingsEntry>

      <SettingsEntry id="environment" applies="restart">
        <PerformanceEnvCard />
      </SettingsEntry>
    </Stack>
  );
}
