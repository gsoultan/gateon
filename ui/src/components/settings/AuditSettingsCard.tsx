// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import React from "react";
import {
  Card,
  Title,
  Text,
  Stack,
  Group,
  Switch,
  ThemeIcon,
  Divider,
  NumberInput,
} from "@mantine/core";
import { IconHistory, IconFingerprint, IconArchive } from "@tabler/icons-react";
import type { GlobalConfig, AuditConfig } from "../../types/gateon";
import { StoredSecretInput, type SecretReplaceConfirm } from "./StoredSecretInput";
import { useAdminOnlySetting } from "../../hooks/usePermissions";
import { AdminOnlyNote } from "./adminOnly/AdminOnlyNote";

// generateSignatureKey returns a cryptographically-random 256-bit key as hex,
// matching the backend's audit.GenerateSignatureKey format.
function generateSignatureKey(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// What replacing the audit key does to the chain already written. Entries are
// signed with one key and verified with one key, and no entry records which
// key signed it, so the entries before a rotation verify only with the key
// being replaced -- which the gateway no longer shows anyone.
const AUDIT_KEY_ROTATION: SecretReplaceConfirm = {
  title: "Replace the audit signing key?",
  consequences:
    "When you save, new audit entries are signed with the new key. Entries written before then " +
    "verify only with the current key, which the gateway does not show: if you will need to verify " +
    "them, copy the key from global.json on the gateway host before you save.",
  confirmLabel: "Replace the audit key on save",
};

interface AuditSettingsCardProps {
  config: GlobalConfig;
  onChange: (config: GlobalConfig) => void;
  disabled?: boolean;
}

export const AuditSettingsCard: React.FC<AuditSettingsCardProps> = ({
  config,
  onChange,
  disabled: formDisabled,
}) => {
  const { disabled, locked } = useAdminOnlySetting(!!formDisabled);
  const audit = config.audit || { enabled: false, signEntries: false };

  const updateAudit = (value: Partial<AuditConfig>) => {
    onChange({
      ...config,
      audit: {
        ...audit,
        ...value,
      },
    });
  };

  const retentionDays = audit.retentionDays || 0;
  const archiveOnRetention = !!audit.archiveOnRetention;

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
            aria-label="Forensic audit logging"
            disabled={disabled}
            size="lg"
          />
        </Group>
        <AdminOnlyNote locked={locked} />

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
                  checked={audit.signEntries}
                  onChange={(e) => updateAudit({ signEntries: e.currentTarget.checked })}
                  aria-label="Cryptographic signing"
                  disabled={disabled}
                />
              </Group>

              {audit.signEntries && (
                <Group gap="xs" align="flex-start" wrap="nowrap">
                  <IconFingerprint size={16} style={{ marginTop: 4 }} />
                  <StoredSecretInput
                    label="Signature Key"
                    placeholder="Enter a key, generate one, or leave blank to have one generated on save"
                    value={audit.signatureKey}
                    onChange={(signatureKey) => updateAudit({ signatureKey })}
                    disabled={disabled}
                    generate={generateSignatureKey}
                    confirm={AUDIT_KEY_ROTATION}
                    description="HMAC-SHA256 key. It is needed to verify the audit chain, and the gateway will not show it."
                  />
                </Group>
              )}

              <Divider variant="dashed" />

              <Stack gap="md">
                <Group justify="space-between">
                  <Stack gap={0}>
                    <Text fw={500}>Log Retention</Text>
                    <Text size="xs" c="dimmed">Number of days to keep audit logs in the active database.</Text>
                  </Stack>
                  <NumberInput
                    min={0}
                    max={3650}
                    value={retentionDays}
                    aria-label="Audit log retention in the database (days)"
                    onChange={(val) => updateAudit({ retentionDays: Number(val) })}
                    disabled={disabled}
                    w={100}
                    suffix=" days"
                  />
                </Group>

                <Group justify="space-between">
                  <Stack gap={0}>
                    <Group gap="xs">
                      <IconArchive size={16} color="var(--mantine-color-grape-6)" />
                      <Text fw={500}>Archive on Retention</Text>
                    </Group>
                    <Text size="xs" c="dimmed">
                      Compress and archive old logs as Brotli-encoded files when they are removed from the database.
                    </Text>
                  </Stack>
                  <Switch
                    checked={archiveOnRetention}
                    aria-label="Archive on retention"
                    onChange={(e) => updateAudit({ archiveOnRetention: e.currentTarget.checked })}
                    disabled={disabled || retentionDays === 0}
                  />
                </Group>
              </Stack>
            </Stack>
          </>
        )}
      </Stack>
    </Card>
  );
};
