// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Stack } from "@mantine/core";
import { SettingsEntry } from "../AppliesChip";
import { UpdateSettingsCard } from "../update/UpdateSettingsCard";
import { UpdateStatusCard } from "../update/UpdateStatusCard";
import type { SettingsTabProps } from "./settingsState";

// The version this gateway runs, whether a newer one exists, and whether and
// where the gateway asks (ADR 0085).
export default function UpdatesTab({ settings }: SettingsTabProps) {
  const { config, setConfig, formDisabled } = settings;
  return (
    <Stack gap="xl">
      <Stack id="software-update" style={{ scrollMarginTop: 80 }}>
        <UpdateStatusCard />
      </Stack>

      <SettingsEntry id="update-check" applies="now">
        <UpdateSettingsCard config={config} onChange={setConfig} disabled={formDisabled} />
      </SettingsEntry>
    </Stack>
  );
}
