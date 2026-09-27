// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Card, Code, Group, NumberInput, Stack, Switch, Text, ThemeIcon, Title } from "@mantine/core";
import { IconArchive } from "@tabler/icons-react";
import type { GlobalConfig, LogConfig } from "../../types/gateon";

interface TraceArchiveSettingsCardProps {
  config: GlobalConfig;
  onChange: (config: GlobalConfig) => void;
  disabled?: boolean;
}

// A number input's value as a config value: empty means "use the profile's
// default", which the gateway reads as zero.
const orZero = (v: string | number) => (typeof v === "number" && v > 0 ? Math.floor(v) : 0);

// TraceArchiveSettingsCard turns the trace archive on and sizes it. The
// archive is off until someone turns it on here: it writes to a disk every
// existing install has budgeted for something else.
export function TraceArchiveSettingsCard({ config, onChange, disabled }: TraceArchiveSettingsCardProps) {
  const log = config.log || {};
  const update = (value: Partial<LogConfig>) => onChange({ ...config, log: { ...log, ...value } });

  return (
    <Card withBorder radius="md" p="xl" shadow="sm">
      <Stack gap="lg">
        <Group justify="space-between" wrap="nowrap">
          <Group wrap="nowrap">
            <ThemeIcon size="xl" radius="md" variant="light" color="indigo">
              <IconArchive size={24} />
            </ThemeIcon>
            <Stack gap={0}>
              <Title order={3}>Trace archive</Title>
              <Text size="sm" c="dimmed">
                Keep traces after the live store lets them go, one compressed file per hour, and search them by period
                in Traces.
              </Text>
            </Stack>
          </Group>
          <Switch
            aria-label="Archive traces"
            checked={!!log.traceArchiveEnabled}
            onChange={(e) => update({ traceArchiveEnabled: e.currentTarget.checked })}
            disabled={disabled}
            size="lg"
          />
        </Group>

        <Group grow align="flex-start">
          <NumberInput
            label="Keep archived hours for (days)"
            placeholder="Profile default"
            description="Empty uses the resource profile's: 7, 90 or 365 days."
            min={1}
            max={3650}
            allowDecimal={false}
            value={log.traceArchiveRetentionDays || ""}
            onChange={(v) => update({ traceArchiveRetentionDays: orZero(v) })}
            disabled={disabled}
            radius="md"
          />
          <NumberInput
            label="Archive size limit (MB)"
            placeholder="Profile default"
            description="Empty uses the resource profile's: 256 MB, 2 GB or 20 GB."
            min={1}
            allowDecimal={false}
            value={log.traceArchiveMaxSizeMb || ""}
            onChange={(v) => update({ traceArchiveMaxSizeMb: orZero(v) })}
            disabled={disabled}
            radius="md"
          />
        </Group>

        <Text size="xs" c="dimmed">
          A few minutes after each hour ends, its traces are written to{" "}
          <Code>trace_archive/2026/09/26/traces-2026-09-26T14Z.ndjson.zst</Code> under the gateway's data directory —
          one file per UTC hour, named for the hour it holds. When either limit is reached the oldest hours go first.
          Changes apply within a minute, without a restart; <Code>GATEON_TRACE_ARCHIVE_*</Code> environment variables,
          where set, take precedence.
        </Text>
      </Stack>
    </Card>
  );
}
