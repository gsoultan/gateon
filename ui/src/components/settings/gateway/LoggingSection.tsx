// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Text, NumberInput, Group, Divider, Switch, Box, Select } from "@mantine/core";
import type { LogConfig } from "../../../types/gateon";

interface LoggingSectionProps {
  log: LogConfig;
  onChange: (log: LogConfig) => void;
  disabled: boolean;
}

// Log level and format, and how long each kind of record is kept.
export function LoggingSection({ log, onChange, disabled }: LoggingSectionProps) {
  return (
    <Box>
      <Divider
        label={
          <Text size="xs" fw={800}>
            LOGGING
          </Text>
        }
        labelPosition="left"
        mb="md"
      />
      <Group grow align="flex-end">
        <Select
          label="Log Level"
          disabled={disabled}
          data={[
            { label: "Debug", value: "debug" },
            { label: "Info", value: "info" },
            { label: "Warn", value: "warn" },
            { label: "Error", value: "error" },
          ]}
          value={log.level || "info"}
          onChange={(v) =>
            onChange({ ...log, level: v || "info" })
          }
          radius="md"
        />
        <Select
          label="Log Format"
          disabled={disabled}
          data={[
            { label: "Text (Console)", value: "text" },
            { label: "JSON", value: "json" },
          ]}
          value={log.format || "text"}
          onChange={(v) =>
            onChange({
              ...log,
              format: (v as "json" | "text") || "text",
            })
          }
          radius="md"
        />
        <Switch
          label="Development Mode"
          checked={log.development || false}
          disabled={disabled}
          onChange={(e) =>
            onChange({
              ...log,
              development: e.currentTarget.checked,
            })
          }
          mb="xs"
        />
        <NumberInput
          label="Path metrics retention (days)"
          description="Aggregated path metrics"
          disabled={disabled}
          min={1}
          max={365}
          value={log.pathStatsRetentionDays ?? 7}
          onChange={(v) =>
            onChange({
              ...log,
              pathStatsRetentionDays: typeof v === 'number' ? v : 7,
            })
          }
          radius="md"
        />
        <NumberInput
          label="Access log retention (days)"
          description="Detailed request traces"
          disabled={disabled}
          min={1}
          max={365}
          value={log.accessLogRetentionDays ?? 7}
          onChange={(v) =>
            onChange({
              ...log,
              accessLogRetentionDays: typeof v === 'number' ? v : 7,
            })
          }
          radius="md"
        />
        <NumberInput
          label="Security threats retention (days)"
          description="WAF and anomaly logs"
          disabled={disabled}
          min={1}
          max={365}
          value={log.securityThreatRetentionDays ?? 30}
          onChange={(v) =>
            onChange({
              ...log,
              securityThreatRetentionDays: typeof v === 'number' ? v : 30,
            })
          }
          radius="md"
        />
        <NumberInput
          label="Audit log retention (days)"
          description="System changes and login logs"
          disabled={disabled}
          min={1}
          max={365}
          value={log.auditLogRetentionDays ?? 90}
          onChange={(v) =>
            onChange({
              ...log,
              auditLogRetentionDays: typeof v === 'number' ? v : 90,
            })
          }
          radius="md"
        />
      </Group>
    </Box>
  );
}
