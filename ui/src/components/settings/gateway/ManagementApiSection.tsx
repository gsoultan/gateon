// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Text, Stack, TextInput, Group, Divider, Box } from "@mantine/core";
import { IconServer } from "@tabler/icons-react";
import type { ManagementConfig } from "../../../types/gateon";

interface ManagementApiSectionProps {
  management: ManagementConfig;
  onChange: (management: ManagementConfig) => void;
  disabled: boolean;
}

// Where the Management API and the dashboard are served, and to whom.
export function ManagementApiSection({ management, onChange, disabled }: ManagementApiSectionProps) {
  return (
    <Box>
      <Divider
        label={
          <Group gap={4}>
            <IconServer size={14} />
            <Text size="xs" fw={800}>
              MANAGEMENT API
            </Text>
          </Group>
        }
        labelPosition="left"
        mb="md"
      />
      <Text size="xs" c="dimmed" mb="sm">
        Configure where Gateon's Management API and Dashboard are served.
      </Text>
      <Stack gap="sm">
        <Group grow>
          <TextInput
            label="Bind Address"
            placeholder="0.0.0.0"
            disabled={disabled}
            value={management.bind || ""}
            onChange={(e) =>
              onChange({ ...management, bind: e.currentTarget.value })
            }
            radius="md"
          />
          <TextInput
            label="Port"
            placeholder="8080"
            disabled={disabled}
            value={management.port || ""}
            onChange={(e) =>
              onChange({ ...management, port: e.currentTarget.value })
            }
            radius="md"
          />
        </Group>
        <TextInput
          label="Management Domain / Host"
          placeholder="admin.example.com"
          description="If set, the management interface will only be accessible via this domain."
          disabled={disabled}
          value={(management.allowedHosts || [])[0] || ""}
          onChange={(e) =>
            onChange({
              ...management,
              allowedHosts: e.currentTarget.value ? [e.currentTarget.value] : [],
            })
          }
          radius="md"
        />
        <TextInput
          label="Allowed IPs (comma-separated CIDRs)"
          placeholder="0.0.0.0/0, ::/0"
          disabled={disabled}
          value={(management.allowedIps || []).join(", ")}
          onChange={(e) =>
            onChange({
              ...management,
              allowedIps: e.currentTarget.value
                .split(",")
                .map((s) => s.trim())
                .filter(Boolean),
            })
          }
          radius="md"
        />
      </Stack>
    </Box>
  );
}
