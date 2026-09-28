// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Card, Title, Text, Stack, Button, Group, Divider, Paper } from "@mantine/core";
import { IconShieldLock, IconUsers, IconKey } from "@tabler/icons-react";
import { Link } from "@tanstack/react-router";

// Where the control plane's users and API keys are managed.
export function AccessControlCard() {
  return (
    <Card withBorder padding="xl" radius="lg" shadow="xs">
      <Stack gap="lg">
        <Group gap="md">
          <Paper p="xs" radius="md" bg="orange.6">
            <IconShieldLock size={20} color="white" />
          </Paper>
          <div>
            <Title order={4} fw={700}>
              Access Control (RBAC)
            </Title>
            <Text c="dimmed" size="xs">
              Manage users and API keys for the Gateway control plane.
            </Text>
          </div>
        </Group>
        <Divider />
        <Stack gap="sm">
          <Group>
            <IconUsers size={18} color="var(--mantine-color-indigo-6)" />
            <Text size="sm" fw={600}>
              User Management
            </Text>
            <Button
              component={Link}
              to="/users"
              variant="light"
              size="xs"
              radius="md"
            >
              Go to Users
            </Button>
          </Group>
          <Group>
            <IconKey size={18} color="var(--mantine-color-dimmed)" />
            <Text size="sm" c="dimmed">
              API Keys for programmatic access — Coming soon
            </Text>
          </Group>
        </Stack>
      </Stack>
    </Card>
  );
}
