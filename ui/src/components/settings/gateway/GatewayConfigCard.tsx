// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Card, Title, Text, Stack, Button, Group, Alert, Paper } from "@mantine/core";
import { IconInfoCircle, IconNetwork } from "@tabler/icons-react";
import type { GlobalConfig } from "../../../types/gateon";
import { TlsSection } from "./TlsSection";
import { RedisSection } from "./RedisSection";
import { ConnectionPoolSection } from "./ConnectionPoolSection";
import { OpenTelemetrySection } from "./OpenTelemetrySection";
import { ManagementApiSection } from "./ManagementApiSection";
import { LoggingSection } from "./LoggingSection";
import { AuthSection } from "./AuthSection";

interface GatewayConfigCardProps {
  config: GlobalConfig;
  onChange: (config: GlobalConfig) => void;
  disabled: boolean;
  canEdit: boolean;
  saving: boolean;
  onSave: () => void;
}

// GatewayConfigCard holds the server-wide sections of the global
// configuration. Each section edits its own slice; this card puts the slices
// back together, so a section cannot write over another's settings.
export function GatewayConfigCard({ config, onChange, disabled, canEdit, saving, onSave }: GatewayConfigCardProps) {
  return (
    <Card withBorder padding="xl" radius="lg" shadow="xs">
      <Stack gap="lg">
        <Group gap="md">
          <Paper p="xs" radius="md" bg="indigo.6">
            <IconNetwork size={20} color="white" />
          </Paper>
          <div>
            <Title order={4} fw={700}>
              Gateway Configuration
            </Title>
            <Text c="dimmed" size="xs">
              Manage server-wide settings: TLS, Redis, transport pooling, and telemetry.
            </Text>
          </div>
        </Group>

        <Alert
          icon={<IconInfoCircle size={16} />}
          color="blue"
          variant="light"
          radius="md"
        >
          Redis and OpenTelemetry apply after a restart. Certificates, TLS versions and ciphers,
          client-certificate settings and ACME apply as soon as they are saved. Transport settings apply to new
          proxy connections.
        </Alert>

        <TlsSection tls={config.tls || { enabled: false }} onChange={(tls) => onChange({ ...config, tls })} disabled={disabled} />
        <RedisSection redis={config.redis || { enabled: false }} onChange={(redis) => onChange({ ...config, redis })} disabled={disabled} />
        <ConnectionPoolSection transport={config.transport || {}} onChange={(transport) => onChange({ ...config, transport })} disabled={disabled} />
        <OpenTelemetrySection otel={config.otel || { enabled: false }} onChange={(otel) => onChange({ ...config, otel })} disabled={disabled} />
        <ManagementApiSection management={config.management || {}} onChange={(management) => onChange({ ...config, management })} disabled={disabled} />
        <LoggingSection log={config.log || {}} onChange={(log) => onChange({ ...config, log })} disabled={disabled} />
        <AuthSection auth={config.auth || {}} onChange={(auth) => onChange({ ...config, auth })} disabled={disabled} />

        {canEdit && (
          <Group justify="flex-end" mt="md">
            <Button
              onClick={onSave}
              loading={saving}
              radius="md"
              px="xl"
            >
              Save Gateway Config
            </Button>
          </Group>
        )}
      </Stack>
    </Card>
  );
}
