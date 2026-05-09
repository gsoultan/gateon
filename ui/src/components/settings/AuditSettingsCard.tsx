import React from "react";
import {
  Card,
  Title,
  Text,
  Stack,
  Group,
  Switch,
  TextInput,
  ThemeIcon,
  Divider,
} from "@mantine/core";
import { IconHistory, IconFingerprint } from "@tabler/icons-react";
import type { GlobalConfig, AuditConfig } from "../../types/gateon";

interface AuditSettingsCardProps {
  config: GlobalConfig;
  onChange: (config: GlobalConfig) => void;
  disabled?: boolean;
}

export const AuditSettingsCard: React.FC<AuditSettingsCardProps> = ({
  config,
  onChange,
  disabled,
}) => {
  const audit = config.audit || { enabled: false, sign_entries: false };

  const updateAudit = (value: Partial<AuditConfig>) => {
    onChange({
      ...config,
      audit: {
        ...audit,
        ...value,
      },
    });
  };

  return (
    <Card withBorder radius="md" p="xl" shadow="sm">
      <Stack gap="xl">
        <Group justify="space-between">
          <Group>
            <ThemeIcon size="xl" radius="md" variant="light" color="grape">
              <IconHistory size={24} />
            </ThemeIcon>
            <Stack gap={0}>
              <Title order={3}>Forensic Audit Logging</Title>
              <Text size="sm" c="dimmed">
                Track all administrative actions and security responses with tamper-proof logging.
              </Text>
            </Stack>
          </Group>
          <Switch
            checked={audit.enabled}
            onChange={(e) => updateAudit({ enabled: e.currentTarget.checked })}
            disabled={disabled}
            size="lg"
          />
        </Group>

        {audit.enabled && (
          <>
            <Divider />
            <Stack gap="md">
              <Group justify="space-between">
                <Stack gap={0}>
                  <Text fw={500}>Cryptographic Signing</Text>
                  <Text size="xs" c="dimmed">Sign audit log entries with HMAC-SHA256 to prevent tampering.</Text>
                </Stack>
                <Switch
                  checked={audit.sign_entries}
                  onChange={(e) => updateAudit({ sign_entries: e.currentTarget.checked })}
                  disabled={disabled}
                />
              </Group>

              {audit.sign_entries && (
                <TextInput
                  label="Signature Key"
                  placeholder="Enter secret key for HMAC"
                  type="password"
                  value={audit.signature_key || ""}
                  onChange={(e) => updateAudit({ signature_key: e.currentTarget.value })}
                  disabled={disabled}
                  leftSection={<IconFingerprint size={16} />}
                />
              )}
            </Stack>
          </>
        )}
      </Stack>
    </Card>
  );
};
