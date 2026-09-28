// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Stack, useMantineColorScheme } from "@mantine/core";
import { ConfigImportExportCard } from "../../ConfigImportExportCard";
import { GeneralSettingsCard } from "../GeneralSettingsCard";
import { ResourceProfileCard } from "../ResourceProfileCard";
import { AppearanceCard } from "../AppearanceCard";
import type { SettingsTabProps } from "./settingsState";

// The dashboard's own preferences, configuration import and export, and the
// resource profile the gateway runs.
export default function GeneralTab({ settings }: SettingsTabProps) {
  const { config, setConfig, status } = settings;
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  return (
    <Stack gap="xl">
      <ConfigImportExportCard canImport={settings.canImportConfig} canExport={settings.canExportConfig} />

      <GeneralSettingsCard
        apiUrlDraft={settings.apiUrlDraft}
        setApiUrlDraft={settings.setApiUrlDraft}
        refreshIntervalDraft={settings.refreshIntervalDraft}
        setRefreshIntervalDraft={settings.setRefreshIntervalDraft}
        generalSavedOk={settings.generalSavedOk}
        onSave={settings.saveGeneral}
      />

      <ResourceProfileCard
        // The profile the gateway runs, where the configured one is not it:
        // GATEON_PROFILE pins the tier over config.profile, and an empty
        // config.profile is resolved by the gateway. The card used to show
        // config.profile (or "standard" when empty) beside "Pinned by
        // Environment", naming a profile the gateway was not running.
        profile={status?.profilePinned || !config.profile ? status?.profile || config.profile || "" : config.profile}
        pinned={status?.profilePinned}
        disabled={settings.formDisabled}
        onChange={(val) => setConfig({ ...config, profile: val })}
      />

      <AppearanceCard colorScheme={colorScheme} setColorScheme={setColorScheme} />
    </Stack>
  );
}
