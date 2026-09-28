// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Card, Title, Text, Stack, TextInput, NumberInput, Button, Group, Switch } from "@mantine/core";
import { IconServer } from "@tabler/icons-react";
import type { HaConfig } from "../../../types/gateon";

interface HighAvailabilityCardProps {
  ha: HaConfig | undefined;
  onChange: (ha: HaConfig) => void;
  disabled: boolean;
  canEdit: boolean;
  saving: boolean;
  onSave: () => void;
}

// Active-passive failover between gateways sharing a virtual IP.
export function HighAvailabilityCard({ ha, onChange, disabled, canEdit, saving, onSave }: HighAvailabilityCardProps) {
  return (
    <Card withBorder shadow="sm" radius="md">
      <Stack gap="md">
        <Group justify="space-between">
          <Group gap="xs">
            <IconServer color="var(--mantine-color-teal-filled)" />
            <Title order={3}>High Availability (VRRP)</Title>
          </Group>
          <Switch
            label="Enable HA"
            checked={ha?.enabled || false}
            onChange={(e) =>
              onChange({
                ...(ha || {
                  priority: 100,
                  virtualRouterId: 51,
                  advertInt: 1,
                }),
                enabled: e.currentTarget.checked,
              })
            }
            disabled={disabled}
          />
        </Group>
        <Text size="sm" c="dimmed">
          Configure Active-Passive failover using VRRP-like protocol. Requires VIP management permissions.
        </Text>

        {ha?.enabled && (
          <Stack gap="sm">
            <TextInput
              label="Network Interface"
              placeholder="eth0"
              value={ha.interface || ""}
              onChange={(e) => onChange({...ha!, interface: e.currentTarget.value})}
              disabled={disabled}
            />
            <Group grow>
              <NumberInput
                label="Virtual Router ID"
                min={1}
                max={255}
                value={ha.virtualRouterId}
                onChange={(v) => onChange({...ha!, virtualRouterId: Number(v)})}
                disabled={disabled}
              />
              <NumberInput
                label="Priority"
                min={1}
                max={255}
                value={ha.priority}
                onChange={(v) => onChange({...ha!, priority: Number(v)})}
                disabled={disabled}
              />
            </Group>
            <TextInput
              label="Virtual IPs (comma-separated)"
              placeholder="192.168.1.100/24"
              value={(ha.virtualIps || []).join(", ")}
              onChange={(e) => onChange({...ha!, virtualIps: e.currentTarget.value.split(",").map(s => s.trim()).filter(Boolean)})}
              disabled={disabled}
            />
            {canEdit && (
              <Group justify="flex-end" mt="md">
                <Button onClick={onSave} loading={saving} size="sm">
                  Save HA Settings
                </Button>
              </Group>
            )}
          </Stack>
        )}
      </Stack>
    </Card>
  );
}
