// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Text, NumberInput, Group, Divider, Box } from "@mantine/core";
import { IconChartDots } from "@tabler/icons-react";
import type { TransportConfig } from "../../../types/gateon";

interface ConnectionPoolSectionProps {
  transport: TransportConfig;
  onChange: (transport: TransportConfig) => void;
  disabled: boolean;
}

// The HTTP transport's idle-connection pool towards backends.
export function ConnectionPoolSection({ transport, onChange, disabled }: ConnectionPoolSectionProps) {
  return (
    <Box>
      <Divider
        label={
          <Group gap={4}>
            <IconChartDots size={14} />
            <Text size="xs" fw={800}>
              PERFORMANCE — CONNECTION POOL
            </Text>
          </Group>
        }
        labelPosition="left"
        mb="md"
      />
      <Text size="xs" c="dimmed" mb="sm">
        Tune HTTP transport for high-throughput backends. Zero = use default.
      </Text>
      <Group grow>
        <NumberInput
          label="Max Idle Conns"
          description="Total idle connections (default 10000)"
          disabled={disabled}
          value={transport.maxIdleConns || ""}
          onChange={(val) =>
            onChange({
              ...transport,
              maxIdleConns: val ? Number(val) : 0,
            })
          }
          min={0}
          placeholder="10000"
          radius="md"
        />
        <NumberInput
          label="Max Idle Conns Per Host"
          description="Per backend host (default 1000)"
          disabled={disabled}
          value={transport.maxIdleConnsPerHost || ""}
          onChange={(val) =>
            onChange({
              ...transport,
              maxIdleConnsPerHost: val ? Number(val) : 0,
            })
          }
          min={0}
          placeholder="1000"
          radius="md"
        />
        <NumberInput
          label="Idle Conn Timeout (seconds)"
          description="Default 90"
          disabled={disabled}
          value={transport.idleConnTimeoutSeconds || ""}
          onChange={(val) =>
            onChange({
              ...transport,
              idleConnTimeoutSeconds: val ? Number(val) : 0,
            })
          }
          min={0}
          placeholder="90"
          radius="md"
        />
      </Group>
    </Box>
  );
}
