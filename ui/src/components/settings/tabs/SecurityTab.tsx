// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Stack } from "@mantine/core";
import { SettingsEntry } from "../AppliesChip";
import { GeoIPSettingsCard } from "../GeoIPSettingsCard";
import { AccessControlCard } from "../security/AccessControlCard";
import { AnomalyDetectionCard } from "../security/AnomalyDetectionCard";
import { WafSettingsCard } from "../security/WafSettingsCard";
import { SecurityAdvancedSettingsCard } from "../SecurityAdvancedSettingsCard";
import type { SettingsTabProps } from "./settingsState";

// Access control, the global WAF and the malware scanner inside it,
// detection, GeoIP and the advanced protections. Every card here applies
// when saved: the WAF cache and the routes are rebuilt on the save.
export default function SecurityTab({ settings }: SettingsTabProps) {
  const { config, setConfig, formDisabled } = settings;
  return (
    <Stack gap="xl">
      <SettingsEntry id="access" applies="now">
        <AccessControlCard />
      </SettingsEntry>

      <SettingsEntry id="waf" applies="now">
        <WafSettingsCard
          waf={config.waf}
          onChange={(waf) => setConfig({ ...config, waf })}
          disabled={formDisabled}
          status={settings.status}
          installing={settings.installing}
          uninstalling={settings.uninstalling}
          onInstall={settings.installClamav}
          onUninstall={settings.uninstallClamav}
        />
      </SettingsEntry>

      <SettingsEntry id="anomaly" applies="now">
        <AnomalyDetectionCard
          anomalyDetection={config.anomalyDetection}
          onChange={(anomalyDetection) => setConfig({ ...config, anomalyDetection })}
          disabled={formDisabled}
        />
      </SettingsEntry>

      <SettingsEntry id="geoip" applies="now">
        <GeoIPSettingsCard config={config.geoip || {}} onChange={(geoip) => setConfig({ ...config, geoip })} disabled={formDisabled} />
      </SettingsEntry>

      <SettingsEntry id="advanced" applies="now">
        <SecurityAdvancedSettingsCard config={config} onChange={setConfig} disabled={formDisabled} />
      </SettingsEntry>
    </Stack>
  );
}
