// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Card, Title, Text, Stack, Group, Paper } from "@mantine/core";
import { IconNetwork } from "@tabler/icons-react";
import type { GlobalConfig } from "../../../types/gateon";
import { TlsSection } from "./TlsSection";
import { ConnectionPoolSection } from "./ConnectionPoolSection";
import { ManagementApiSection } from "./ManagementApiSection";
import { AuthSection } from "./AuthSection";

interface GatewayConfigCardProps {
  config: GlobalConfig;
  onChange: (config: GlobalConfig) => void;
  disabled: boolean;
}

// GatewayConfigCard holds the server-wide sections of the global
// configuration. Each section edits its own slice; this card puts the slices
// back together, so a section cannot write over another's settings.
export function GatewayConfigCard({ config, onChange, disabled }: GatewayConfigCardProps) {
  return (
    <Card withBorder padding="xl" radius="lg" shadow="xs">
      <Stack gap="lg">
        <Group gap="md">
          <Paper p="xs" radius="md" bg="indigo.6">
            <IconNetwork size={20} color="white" />
          </Paper>
          <div>
            <Title order={4} fw={700}>
              Gateway
            </Title>
            <Text c="dimmed" size="xs">
              TLS and ACME apply when saved; transport settings apply to new connections; the management bind applies after a restart.
            </Text>
          </div>
        </Group>

        <TlsSection tls={config.tls || { enabled: false }} onChange={(tls) => onChange({ ...config, tls })} disabled={disabled} />
        <ConnectionPoolSection transport={config.transport || {}} onChange={(transport) => onChange({ ...config, transport })} disabled={disabled} />
        <ManagementApiSection management={config.management || {}} onChange={(management) => onChange({ ...config, management })} disabled={disabled} />
        <AuthSection auth={config.auth || {}} onChange={(auth) => onChange({ ...config, auth })} disabled={disabled} />
      </Stack>
    </Card>
  );
}
