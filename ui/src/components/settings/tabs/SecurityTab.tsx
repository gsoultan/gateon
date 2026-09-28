// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Stack } from "@mantine/core";
import { AccessControlCard } from "../security/AccessControlCard";
import { WafSettingsCard } from "../security/WafSettingsCard";
import { AnomalyDetectionCard } from "../security/AnomalyDetectionCard";
import { GeoIPSettingsCard } from "../GeoIPSettingsCard";
import { SecurityAdvancedSettingsCard } from "../SecurityAdvancedSettingsCard";
import { AlertingSettingsCard } from "../AlertingSettingsCard";
import { AuditSettingsCard } from "../AuditSettingsCard";
import type { SettingsTabProps } from "./settingsState";

// Access control, the global WAF, detection, GeoIP, advanced protections,
// alerting and the forensic audit log.
export default function SecurityTab({ settings }: SettingsTabProps) {
  const { config, setConfig, formDisabled, canEditGlobal, saving, saveGatewayConfig } = settings;
  return (
    <Stack gap="xl">
      <AccessControlCard />

      <WafSettingsCard
        waf={config.waf}
        onChange={(waf) => setConfig({ ...config, waf })}
        disabled={formDisabled}
        canEdit={canEditGlobal}
        saving={saving}
        onSave={saveGatewayConfig}
        onUpdateRules={settings.triggerWafUpdate}
        status={settings.status}
        installing={settings.installing}
        uninstalling={settings.uninstalling}
        onInstall={settings.installClamav}
        onUninstall={settings.uninstallClamav}
      />

      <AnomalyDetectionCard
        anomalyDetection={config.anomalyDetection}
        onChange={(anomalyDetection) => setConfig({ ...config, anomalyDetection })}
        disabled={formDisabled}
        canEdit={canEditGlobal}
        saving={saving}
        onSave={saveGatewayConfig}
      />

      <GeoIPSettingsCard
        config={config.geoip || {}}
        onChange={(geoip) => setConfig({ ...config, geoip })}
        onSave={saveGatewayConfig}
        saving={saving}
        disabled={formDisabled}
      />

      <SecurityAdvancedSettingsCard config={config} onChange={setConfig} disabled={formDisabled} />

      <AlertingSettingsCard config={config} onChange={setConfig} disabled={formDisabled} />

      <AuditSettingsCard config={config} onChange={setConfig} disabled={formDisabled} />
    </Stack>
  );
}
