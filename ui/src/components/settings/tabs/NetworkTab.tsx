// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Stack } from "@mantine/core";
import { SettingsEntry } from "../AppliesChip";
import { EbpfSettingsCard } from "../network/EbpfSettingsCard";
import { HighAvailabilityCard } from "../network/HighAvailabilityCard";
import type { SettingsTabProps } from "./settingsState";

// Failover between gateways, which the supervisor reconciles on a save, and
// the kernel offload in front of this one, which attaches at start.
export default function NetworkTab({ settings }: SettingsTabProps) {
  const { config, setConfig, formDisabled } = settings;
  return (
    <Stack gap="xl">
      <SettingsEntry id="ha" applies="now">
        <HighAvailabilityCard ha={config.ha} onChange={(ha) => setConfig({ ...config, ha })} disabled={formDisabled} />
      </SettingsEntry>

      <SettingsEntry id="ebpf" applies="restart">
        <EbpfSettingsCard ebpf={config.ebpf} onChange={(ebpf) => setConfig({ ...config, ebpf })} disabled={formDisabled} />
      </SettingsEntry>
    </Stack>
  );
}
