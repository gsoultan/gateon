// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Stack } from "@mantine/core";
import { HighAvailabilityCard } from "../network/HighAvailabilityCard";
import { EbpfSettingsCard } from "../network/EbpfSettingsCard";
import type { SettingsTabProps } from "./settingsState";

// Failover between gateways, and the kernel offload in front of this one.
export default function NetworkTab({ settings }: SettingsTabProps) {
  const { config, setConfig, formDisabled, canEditGlobal, saving, saveGatewayConfig } = settings;
  return (
    <Stack gap="xl">
      <HighAvailabilityCard
        ha={config.ha}
        onChange={(ha) => setConfig({ ...config, ha })}
        disabled={formDisabled}
        canEdit={canEditGlobal}
        saving={saving}
        onSave={saveGatewayConfig}
      />

      <EbpfSettingsCard
        ebpf={config.ebpf}
        onChange={(ebpf) => setConfig({ ...config, ebpf })}
        disabled={formDisabled}
        canEdit={canEditGlobal}
        saving={saving}
        onSave={saveGatewayConfig}
      />
    </Stack>
  );
}
