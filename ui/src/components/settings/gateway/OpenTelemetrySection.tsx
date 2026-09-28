// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Text, Stack, TextInput, Group, Divider, Switch, Box } from "@mantine/core";
import type { OtelConfig } from "../../../types/gateon";

interface OpenTelemetrySectionProps {
  otel: OtelConfig;
  onChange: (otel: OtelConfig) => void;
  disabled: boolean;
}

// Where the gateway exports its OpenTelemetry traces.
export function OpenTelemetrySection({ otel, onChange, disabled }: OpenTelemetrySectionProps) {
  return (
    <Box>
      <Divider
        label={
          <Text size="xs" fw={800}>
            OPENTELEMETRY
          </Text>
        }
        labelPosition="left"
        mb="md"
      />
      <Stack gap="sm">
        <Switch
          label="Enable Tracing (OpenTelemetry)"
          checked={otel.enabled || false}
          disabled={disabled}
          onChange={(e) =>
            onChange({ ...otel, enabled: e.currentTarget.checked })
          }
          radius="md"
        />
        <Group grow>
          <TextInput
            label="OTLP HTTP Endpoint"
            placeholder="http://localhost:4318"
            disabled={disabled || !otel.enabled}
            value={otel.endpoint || ""}
            onChange={(e) =>
              onChange({ ...otel, endpoint: e.currentTarget.value })
            }
            radius="md"
          />
          <TextInput
            label="Service Name"
            placeholder="gateon-gateway"
            disabled={disabled || !otel.enabled}
            value={otel.serviceName || ""}
            onChange={(e) =>
              onChange({ ...otel, serviceName: e.currentTarget.value })
            }
            radius="md"
          />
        </Group>
      </Stack>
    </Box>
  );
}
