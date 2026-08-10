// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Card, Title, Text, Stack, Group, Paper, Select, Badge, Alert } from "@mantine/core";
import { IconCpu, IconInfoCircle, IconAlertTriangle } from "@tabler/icons-react";

interface ResourceProfileCardProps {
  profile: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  pinned?: boolean;
}

export function ResourceProfileCard({ profile, onChange, disabled, pinned }: ResourceProfileCardProps) {
  return (
    <Card withBorder padding="xl" radius="lg" shadow="xs">
      <Stack gap="lg">
        <Group gap="md">
          <Paper p="xs" radius="md" bg="orange.6">
            <IconCpu size={20} color="white" />
          </Paper>
          <div style={{ flex: 1 }}>
            <Group justify="space-between">
              <div>
                <Title order={4} fw={700}>
                  Resource Profile
                </Title>
                <Text c="dimmed" size="xs">
                  Sizes detection depth and history based on available hardware.
                </Text>
              </div>
              {pinned && (
                <Badge color="orange" variant="light" leftSection={<IconAlertTriangle size={12} />}>
                  Pinned by Environment
                </Badge>
              )}
            </Group>
          </div>
        </Group>

        {pinned && (
          <Alert icon={<IconInfoCircle size={16} />} color="orange" variant="light" radius="md">
            The profile is currently locked via the <Text span fw={700}>GATEON_PROFILE</Text> environment variable. 
            UI changes will only take effect if you unset this variable on the server.
          </Alert>
        )}

        <Select
          label="Active Profile"
          description="Choose a profile that matches your server resources."
          placeholder="Select profile"
          data={[
            { value: "minimal", label: "Minimal (2 Cores, 2GB RAM)" },
            { value: "standard", label: "Standard (4 Cores, 8GB RAM)" },
            { value: "enterprise", label: "Enterprise (8+ Cores, 16GB+ RAM)" },
          ]}
          value={profile || "standard"}
          onChange={(val) => onChange(val || "standard")}
          disabled={disabled || pinned}
          radius="md"
        />

        <Stack gap="xs">
          <Text size="sm" fw={700}>Profile Impacts:</Text>
          <Group gap="xs">
            <Badge size="xs" color="gray">Telemetry Intervals</Badge>
            <Badge size="xs" color="gray">DB Pool Size</Badge>
            <Badge size="xs" color="gray">WAF Depth</Badge>
            <Badge size="xs" color="gray">Retention</Badge>
            <Badge size="xs" color="gray">Memory Caches</Badge>
          </Group>
        </Stack>
      </Stack>
    </Card>
  );
}
