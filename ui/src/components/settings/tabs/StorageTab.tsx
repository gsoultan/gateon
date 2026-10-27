// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Stack } from "@mantine/core";
import { TraceArchiveSettingsCard } from "../../Traces/TraceArchiveSettingsCard";
import { SettingsEntry } from "../AppliesChip";
import { AuditSettingsCard } from "../AuditSettingsCard";
import { LoggingSection } from "../gateway/LoggingSection";
import { ThreatArchiveSettingsCard } from "../ThreatArchiveSettingsCard";
import { SectionCard } from "./SectionCard";
import type { SettingsTabProps } from "./settingsState";

// What the gateway writes down and for how long: the log itself, the
// retention of each kind of record, the two archives and the audit log.
export default function StorageTab({ settings }: SettingsTabProps) {
  const { config, setConfig, formDisabled } = settings;
  return (
    <Stack gap="xl">
      <SettingsEntry id="logging" applies="restart">
        <SectionCard
          title="Logging and retention"
          description="Level and format are read at start. The retention periods apply as soon as they are saved."
        >
          <LoggingSection log={config.log || {}} onChange={(log) => setConfig({ ...config, log })} disabled={formDisabled} />
        </SectionCard>
      </SettingsEntry>

      <SettingsEntry id="trace-archive" applies="now">
        <TraceArchiveSettingsCard config={config} onChange={setConfig} disabled={formDisabled} />
      </SettingsEntry>

      <SettingsEntry id="threat-archive" applies="now">
        <ThreatArchiveSettingsCard config={config} onChange={setConfig} disabled={formDisabled} />
      </SettingsEntry>

      <SettingsEntry id="audit" applies="now">
        <AuditSettingsCard config={config} onChange={setConfig} disabled={formDisabled} />
      </SettingsEntry>
    </Stack>
  );
}
