// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Stack } from "@mantine/core";
import { SettingsEntry } from "../AppliesChip";
import { UpdateSettingsCard } from "../update/UpdateSettingsCard";
import { UpdateStatusCard } from "../update/UpdateStatusCard";
import { AutoInstallCard } from "../update/AutoInstallCard";
import { UpgradeCard } from "../update/UpgradeCard";
import type { SettingsTabProps } from "./settingsState";

// The version this gateway runs, whether a newer one exists, and whether and
// where the gateway asks (ADR 0085); installing one, by hand or on its own,
// and what became of earlier installs (ADR 0087).
export default function UpdatesTab({ settings }: SettingsTabProps) {
  const { config, setConfig, formDisabled } = settings;
  return (
    <Stack gap="xl">
      <Stack id="software-update" style={{ scrollMarginTop: 80 }}>
        <UpdateStatusCard />
      </Stack>

      <Stack id="software-install" style={{ scrollMarginTop: 80 }}>
        <UpgradeCard />
      </Stack>

      <SettingsEntry id="update-check" applies="now">
        <UpdateSettingsCard config={config} onChange={setConfig} disabled={formDisabled} />
      </SettingsEntry>

      <SettingsEntry id="update-auto-install" applies="now">
        <AutoInstallCard config={config} onChange={setConfig} disabled={formDisabled} />
      </SettingsEntry>
    </Stack>
  );
}
