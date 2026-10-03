// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Text, Stack, TextInput, Group, Divider, Switch, Box, Select, MultiSelect } from "@mantine/core";
import { IconShieldLock } from "@tabler/icons-react";
import type { TlsConfig } from "../../../types/gateon";
import { ACME_CHALLENGE_NOTE, ACME_CHALLENGE_TYPES } from "../acmeChallenges";
import { ADMIN_ONLY_REASON, useAdminOnlySetting } from "../../../hooks/usePermissions";

interface TlsSectionProps {
  tls: TlsConfig;
  onChange: (tls: TlsConfig) => void;
  disabled: boolean;
}

// The gateway's own TLS: domains, ACME, protocol versions, client
// certificates and cipher suites.
export function TlsSection({ tls, onChange, disabled }: TlsSectionProps) {
  // Whether client certificates are demanded is administrator-only (ADR 0040).
  const clientAuth = useAdminOnlySetting(disabled);
  return (
    <Box>
      <Divider
        label={
          <Group gap={4}>
            <IconShieldLock size={14} />
            <Text size="xs" fw={800}>
              TLS
            </Text>
          </Group>
        }
        labelPosition="left"
        mb="md"
      />
      <Stack gap="md">
        <Group grow align="flex-end">
          <Switch
            label="Enable TLS"
            checked={!!tls.enabled}
            disabled={disabled}
            onChange={(e) =>
              onChange({ ...tls, enabled: e.currentTarget.checked })
            }
            size="md"
          />
        </Group>
        {tls.enabled && (
          <>
            <TextInput
              label="Domains (comma-separated)"
              placeholder="example.com, www.example.com"
              disabled={disabled}
              value={(tls.domains || []).join(", ")}
              onChange={(e) =>
                onChange({
                  ...tls,
                  domains: e.currentTarget.value
                    .split(",")
                    .map((s) => s.trim())
                    .filter(Boolean),
                })
              }
              radius="md"
            />
            <Divider
              label={
                <Text size="xs" fw={700}>
                  ACME / Let's Encrypt
                </Text>
              }
              labelPosition="left"
              variant="dashed"
            />
            <Switch
              label="Enable Auto-TLS (ACME)"
              checked={tls.acme?.enabled || false}
              disabled={disabled}
              onChange={(e) =>
                onChange({
                  ...tls,
                  acme: {
                    ...(tls.acme || { enabled: false }),
                    enabled: e.currentTarget.checked,
                  },
                })
              }
              radius="md"
            />
            {tls.acme?.enabled && (
              <Stack gap="sm">
                <TextInput
                  label="ACME Email"
                  placeholder="admin@example.com"
                  disabled={disabled}
                  value={tls.acme.email || ""}
                  onChange={(e) =>
                    onChange({
                      ...tls,
                      acme: {
                        ...tls.acme!,
                        email: e.currentTarget.value,
                      },
                    })
                  }
                  radius="md"
                />
                <TextInput
                  label="ACME Server"
                  placeholder="https://acme-v02.api.letsencrypt.org/directory"
                  disabled={disabled}
                  value={tls.acme.caServer || ""}
                  onChange={(e) =>
                    onChange({
                      ...tls,
                      acme: {
                        ...tls.acme!,
                        caServer: e.currentTarget.value,
                      },
                    })
                  }
                  radius="md"
                />
                <Select
                  label="Challenge Type"
                  description={ACME_CHALLENGE_NOTE}
                  disabled={disabled}
                  data={ACME_CHALLENGE_TYPES}
                  value={tls.acme.challengeType === "tls-alpn" ? "tls-alpn" : "http"}
                  onChange={(v) =>
                    onChange({
                      ...tls,
                      acme: {
                        ...tls.acme!,
                        challengeType: v || "http",
                      },
                    })
                  }
                  radius="md"
                />
              </Stack>
            )}

            <Group grow>
              <Select
                label="Min TLS Version"
                disabled={disabled}
                data={["TLS1.2", "TLS1.3"]}
                value={tls.minTlsVersion || "TLS1.2"}
                onChange={(val) =>
                  onChange({ ...tls, minTlsVersion: val || "TLS1.2" })
                }
                radius="md"
              />
              <Select
                label="Max TLS Version"
                disabled={disabled}
                data={["TLS1.2", "TLS1.3"]}
                value={tls.maxTlsVersion || ""}
                placeholder="Default"
                onChange={(val) =>
                  onChange({ ...tls, maxTlsVersion: val || "" })
                }
                radius="md"
                clearable
              />
            </Group>
            <Select
              label="Client Authentication"
              description={clientAuth.locked ? ADMIN_ONLY_REASON : undefined}
              disabled={clientAuth.disabled}
              data={[
                { label: "No Client Cert", value: "NoClientCert" },
                {
                  label: "Request Client Cert",
                  value: "RequestClientCert",
                },
                {
                  label: "Require Any Client Cert",
                  value: "RequireAnyClientCert",
                },
                {
                  label: "Verify Client Cert If Given",
                  value: "VerifyClientCertIfGiven",
                },
                {
                  label: "Require and Verify Client Cert",
                  value: "RequireAndVerifyClientCert",
                },
              ]}
              value={tls.clientAuthType || "NoClientCert"}
              onChange={(val) =>
                onChange({ ...tls, clientAuthType: val || "NoClientCert" })
              }
              radius="md"
            />
            <MultiSelect
              label="Cipher Suites"
              disabled={disabled}
              placeholder="Select cipher suites"
              data={[
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
              ]}
              value={tls.cipherSuites || []}
              onChange={(val) =>
                onChange({ ...tls, cipherSuites: val })
              }
              radius="md"
              clearable
            />
          </>
        )}
      </Stack>
    </Box>
  );
}
