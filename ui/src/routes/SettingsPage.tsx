// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useState, useEffect } from "react";
import {
  Card,
  Title,
  Text,
  Stack,
  TextInput,
  Textarea,
  NumberInput,
  Button,
  Group,
  Divider,
  Switch,
  useMantineColorScheme,
  Alert,
  Paper,
  Box,
  Select,
  MultiSelect,
  ActionIcon,
  Tooltip,
  Code,
  CopyButton,
  TagsInput,
  Menu,
  Loader,
} from "@mantine/core";
import {
  IconInfoCircle,
  IconNetwork,
  IconShieldLock,
  IconBolt,
  IconCopy,
  IconCheck,
  IconUsers,
  IconKey,
  IconChartDots,
  IconRefresh,
  IconServer,
  IconActivity,
  IconCpu,
  IconDownload,
  IconBox,
  IconChevronDown,
  IconShieldCheck,
  IconX,
  IconAdjustments,
  IconTrash,
  IconAlertTriangle,
} from "@tabler/icons-react";
import { notifications } from '@mantine/notifications';
import { ConfigImportExportCard } from "../components/ConfigImportExportCard";
import {
  GeneralSettingsCard,
  GeoIPSettingsCard,
  SecurityAdvancedSettingsCard,
  AlertingSettingsCard,
  AuditSettingsCard,
  PresetsCard,
  AppearanceCard,
  ResourceProfileCard,
  TitanSettingsCard
} from "../components/settings";
import { usePermissions } from "../hooks/usePermissions";
import { useGateonStatus } from "../hooks/useGateonStatus";
import { useNetworkInterfaces } from "../hooks/useNetworkInterfaces";
import { useApiConfigStore } from "../store/useApiConfigStore";
import type { GlobalConfig, DatabaseConfig } from "../types/gateon";
import { WAF_APP_PROFILES } from "../types/gateon";
import { generateRandomString } from "../utils/random";
import { Link } from "@tanstack/react-router";
import { apiFetch } from "../hooks/useGateon";

function inferDriver(
  databaseUrl?: string,
  sqlitePath?: string
): DatabaseConfig["driver"] {
  const raw = databaseUrl || sqlitePath || "";
  if (raw.startsWith("postgres")) return "postgres";
  if (raw.startsWith("mysql")) return "mysql";
  if (raw.startsWith("mariadb")) return "mariadb";
  return "sqlite";
}

export default function SettingsPage() {
  const { canEditGlobal, canImportConfig, canExportConfig } = usePermissions();
  const { data: status } = useGateonStatus();
  const { data: netInfo, isError: netInfoError } = useNetworkInterfaces();
  const formDisabled = !canEditGlobal;
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  const apiUrl = useApiConfigStore((s) => s.apiUrl);
  const refreshInterval = useApiConfigStore((s) => s.refreshInterval);
  const setApiConfig = useApiConfigStore((s) => s.setApiConfig);

  // Local edits for General Settings (committed on Save)
  const [apiUrlDraft, setApiUrlDraft] = useState(apiUrl);
  const [refreshIntervalDraft, setRefreshIntervalDraft] = useState(refreshInterval);

  useEffect(() => {
    setApiUrlDraft(apiUrl);
    setRefreshIntervalDraft(refreshInterval);
  }, [apiUrl, refreshInterval]);

  // Global config state
  const [config, setConfig] = useState<GlobalConfig>({
    tls: { enabled: false, acme: { enabled: false } },
    redis: { enabled: false },
    otel: { enabled: false },
    log: { level: "info", development: true, format: "text" },
    management: { bind: "0.0.0.0", port: "8080", allowedIps: ["0.0.0.0/0", "::/0"] },
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [savedOk, setSavedOk] = useState(false);
  const [generalSavedOk, setGeneralSavedOk] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [uninstalling, setUninstalling] = useState(false);

  const handleUninstall = async () => {
    setUninstalling(true);
    try {
      const res = await apiFetch("/v1/security/clamav/uninstall", {
        method: "POST",
      });
      const data = await res.json();
      if (res.ok && data.success) {
        notifications.show({
          title: 'Uninstallation Started',
          message: 'ClamAV removal has been initiated. This might take a few minutes.',
          color: 'blue',
          icon: <IconShieldCheck size={16} />
        });
      } else {
        throw new Error(data.message || 'Failed to start uninstallation');
      }
    } catch (err: any) {
      notifications.show({
        title: 'Uninstallation Failed',
        message: err.message || 'Failed to start ClamAV uninstallation',
        color: 'red',
        icon: <IconX size={16} />
      });
    } finally {
      setUninstalling(false);
    }
  };

  const handleInstall = async (mode: number) => {
    setInstalling(true);
    try {
      const res = await apiFetch("/v1/security/clamav/install", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        notifications.show({
          title: 'Installation Started',
          message: 'ClamAV installation has been initiated. This might take a few minutes.',
          color: 'blue',
          icon: <IconShieldCheck size={16} />
        });
      } else {
        throw new Error(data.message || 'Failed to start installation');
      }
    } catch (err: any) {
      notifications.show({
        title: 'Installation Failed',
        message: err.message || 'Failed to start ClamAV installation',
        color: 'red',
        icon: <IconX size={16} />
      });
    } finally {
      setInstalling(false);
    }
  };

  useEffect(() => {
    // Fetch current global config
    const controller = new AbortController();
    apiFetch("/v1/global", {
      signal: controller.signal,
    })
      .then(async (r) => {
        if (!r.ok) throw new Error(await r.text());
        return r.json();
      })
      .then((cfg: GlobalConfig) => setConfig(cfg || ({} as GlobalConfig)))
      .catch(() => {});
    return () => controller.abort();
  }, [apiUrl]);

  const handleSave = () => {
    setApiConfig(apiUrlDraft, refreshIntervalDraft);
    setGeneralSavedOk(true);
    setTimeout(() => setGeneralSavedOk(false), 2000);
  };

  const saveGatewayConfig = async () => {
    setSaving(true);
    setError(null);
    setSavedOk(false);
    try {
      const res = await apiFetch("/v1/global", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(config),
      });
      if (!res.ok) throw new Error(await res.text());
      setSavedOk(true);
    } catch (e: any) {
      setError(e.message || "Failed to save configuration");
    } finally {
      setSaving(false);
    }
  };

  const triggerWafUpdate = async () => {
    setSaving(true);
    setError(null);
    try {
      const res = await apiFetch("/v1/waf/update", {
        method: "POST",
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      if (data.success) {
        setSavedOk(true);
      } else {
        setError(data.message || "Failed to update WAF rules");
      }
    } catch (e: any) {
      setError(e.message || "Failed to trigger WAF update");
    } finally {
      setSaving(false);
    }
  };


  const tls = config.tls || { enabled: false };
  const redis = config.redis || { enabled: false };
  const otel = config.otel || { enabled: false };
  const transport = config.transport || {};

  const applyPreset = (preset: "development" | "production" | "high-throughput") => {
    const base = { ...config };
    if (preset === "development") {
      setConfig({
        ...base,
        log: { level: "debug", development: true, format: "text", pathStatsRetentionDays: 7 },
        tls: { ...tls, enabled: false },
        redis: { ...redis, enabled: false },
        otel: { ...otel, enabled: false },
      });
    } else if (preset === "production") {
      setConfig({
        ...base,
        log: { level: "info", development: false, format: "json", pathStatsRetentionDays: 30 },
        tls: { ...tls, enabled: true },
        redis: { ...redis, enabled: true },
        otel: { ...otel, enabled: true },
      });
    } else if (preset === "high-throughput") {
      setConfig({
        ...base,
        log: { level: "warn", development: false, format: "json", pathStatsRetentionDays: 7 },
        tls: tls,
        redis: redis,
        otel: otel,
        transport: {
          maxIdleConns: 20000,
          maxIdleConnsPerHost: 2000,
          idleConnTimeoutSeconds: 90,
        },
      });
    }
  };

  return (
    <Stack gap="xl">
      <div>
        <Title order={2} fw={800} style={{ letterSpacing: -1 }}>
          Settings
        </Title>
        <Text c="dimmed" size="sm">
          Manage your gateway preferences and UI appearance.
        </Text>
      </div>

      <PresetsCard disabled={formDisabled} onApply={applyPreset} />

      <ConfigImportExportCard canImport={canImportConfig} canExport={canExportConfig} />

      <GeneralSettingsCard
        apiUrlDraft={apiUrlDraft}
        setApiUrlDraft={setApiUrlDraft}
        refreshIntervalDraft={refreshIntervalDraft}
        setRefreshIntervalDraft={setRefreshIntervalDraft}
        generalSavedOk={generalSavedOk}
        onSave={handleSave}
      />

      <ResourceProfileCard
        profile={config.profile || ""}
        pinned={status?.profilePinned}
        disabled={formDisabled}
        onChange={(val) => setConfig({ ...config, profile: val })}
      />

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
            Some settings (TLS, Redis, OTEL) may require a server restart. Transport config applies to new proxy connections.
          </Alert>

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
                  disabled={formDisabled}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      tls: { ...tls, enabled: e.currentTarget.checked },
                    })
                  }
                  size="md"
                />
              </Group>
              {tls.enabled && (
                <>
                  <TextInput
                    label="Domains (comma-separated)"
                    placeholder="example.com, www.example.com"
                    disabled={formDisabled}
                    value={(tls.domains || []).join(", ")}
                    onChange={(e) =>
                      setConfig({
                        ...config,
                        tls: {
                          ...tls,
                          domains: e.currentTarget.value
                            .split(",")
                            .map((s) => s.trim())
                            .filter(Boolean),
                        },
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
                    disabled={formDisabled}
                    onChange={(e) =>
                      setConfig({
                        ...config,
                        tls: {
                          ...tls,
                          acme: {
                            ...(tls.acme || { enabled: false }),
                            enabled: e.currentTarget.checked,
                          },
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
                        disabled={formDisabled}
                        value={tls.acme.email || ""}
                        onChange={(e) =>
                          setConfig({
                            ...config,
                            tls: {
                              ...tls,
                              acme: {
                                ...tls.acme!,
                                email: e.currentTarget.value,
                              },
                            },
                          })
                        }
                        radius="md"
                      />
                      <TextInput
                        label="ACME Server"
                        placeholder="https://acme-v02.api.letsencrypt.org/directory"
                        disabled={formDisabled}
                        value={tls.acme.caServer || ""}
                        onChange={(e) =>
                          setConfig({
                            ...config,
                            tls: {
                              ...tls,
                              acme: {
                                ...tls.acme!,
                                caServer: e.currentTarget.value,
                              },
                            },
                          })
                        }
                        radius="md"
                      />
                      <Select
                        label="Challenge Type"
                        disabled={formDisabled}
                        data={[
                          { label: "HTTP-01", value: "http" },
                          { label: "TLS-ALPN-01", value: "tls-alpn" },
                          { label: "DNS-01", value: "dns" },
                        ]}
                        value={tls.acme.challengeType || "http"}
                        onChange={(v) =>
                          setConfig({
                            ...config,
                            tls: {
                              ...tls,
                              acme: {
                                ...tls.acme!,
                                challengeType: v || "http",
                              },
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
                      disabled={formDisabled}
                      data={["TLS1.2", "TLS1.3"]}
                      value={tls.minTlsVersion || "TLS1.2"}
                      onChange={(val) =>
                        setConfig({
                          ...config,
                          tls: { ...tls, minTlsVersion: val || "TLS1.2" },
                        })
                      }
                      radius="md"
                    />
                    <Select
                      label="Max TLS Version"
                      disabled={formDisabled}
                      data={["TLS1.2", "TLS1.3"]}
                      value={tls.maxTlsVersion || ""}
                      placeholder="Default"
                      onChange={(val) =>
                        setConfig({
                          ...config,
                          tls: { ...tls, maxTlsVersion: val || "" },
                        })
                      }
                      radius="md"
                      clearable
                    />
                  </Group>
                  <Select
                    label="Client Authentication"
                    disabled={formDisabled}
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
                      setConfig({
                        ...config,
                        tls: { ...tls, clientAuthType: val || "NoClientCert" },
                      })
                    }
                    radius="md"
                  />
                  <MultiSelect
                    label="Cipher Suites"
                    disabled={formDisabled}
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
                      setConfig({
                        ...config,
                        tls: { ...tls, cipherSuites: val },
                      })
                    }
                    radius="md"
                    clearable
                  />
                </>
              )}
            </Stack>
          </Box>

          <Box>
            <Divider
              label={
                <Text size="xs" fw={800}>
                  REDIS
                </Text>
              }
              labelPosition="left"
              mb="md"
            />
            <Stack gap="sm">
              <Switch
                label="Enable Redis (rate limiting, token revocation, and distributed cache)"
                checked={redis.enabled || false}
                disabled={formDisabled}
                onChange={(e) =>
                  setConfig({
                    ...config,
                    redis: { ...redis, enabled: e.currentTarget.checked },
                  })
                }
                radius="md"
              />
              <Group grow>
                <TextInput
                  label="Address"
                  placeholder="localhost:6379"
                  disabled={formDisabled || !redis.enabled}
                  value={redis.addr || ""}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      redis: { ...redis, addr: e.currentTarget.value },
                    })
                  }
                  radius="md"
                />
                <TextInput
                  label="Password"
                  type="password"
                  disabled={formDisabled || !redis.enabled}
                  value={redis.password || ""}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      redis: { ...redis, password: e.currentTarget.value },
                    })
                  }
                  radius="md"
                />
              </Group>
            </Stack>
          </Box>

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
                disabled={formDisabled}
                value={transport.maxIdleConns || ""}
                onChange={(val) =>
                  setConfig({
                    ...config,
                    transport: {
                      ...transport,
                      maxIdleConns: val ? Number(val) : 0,
                    },
                  })
                }
                min={0}
                placeholder="10000"
                radius="md"
              />
              <NumberInput
                label="Max Idle Conns Per Host"
                description="Per backend host (default 1000)"
                disabled={formDisabled}
                value={transport.maxIdleConnsPerHost || ""}
                onChange={(val) =>
                  setConfig({
                    ...config,
                    transport: {
                      ...transport,
                      maxIdleConnsPerHost: val ? Number(val) : 0,
                    },
                  })
                }
                min={0}
                placeholder="1000"
                radius="md"
              />
              <NumberInput
                label="Idle Conn Timeout (seconds)"
                description="Default 90"
                disabled={formDisabled}
                value={transport.idleConnTimeoutSeconds || ""}
                onChange={(val) =>
                  setConfig({
                    ...config,
                    transport: {
                      ...transport,
                      idleConnTimeoutSeconds: val ? Number(val) : 0,
                    },
                  })
                }
                min={0}
                placeholder="90"
                radius="md"
              />
            </Group>
          </Box>

          <Box>
            <Divider
              label={
                <Text size="xs" fw={800}>
                  OPENTELEMETRY
                </Text>
              }
              labelPosition="left"
              mb="md"
            />
            <Stack gap="sm">
              <Switch
                label="Enable Tracing (OpenTelemetry)"
                checked={otel.enabled || false}
                disabled={formDisabled}
                onChange={(e) =>
                  setConfig({
                    ...config,
                    otel: { ...otel, enabled: e.currentTarget.checked },
                  })
                }
                radius="md"
              />
              <Group grow>
                <TextInput
                  label="OTLP HTTP Endpoint"
                  placeholder="http://localhost:4318"
                  disabled={formDisabled || !otel.enabled}
                  value={otel.endpoint || ""}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      otel: { ...otel, endpoint: e.currentTarget.value },
                    })
                  }
                  radius="md"
                />
                <TextInput
                  label="Service Name"
                  placeholder="gateon-gateway"
                  disabled={formDisabled || !otel.enabled}
                  value={otel.serviceName || ""}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      otel: { ...otel, serviceName: e.currentTarget.value },
                    })
                  }
                  radius="md"
                />
              </Group>
            </Stack>
          </Box>

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
                  disabled={formDisabled}
                  value={config.management?.bind || ""}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      management: { ...(config.management || {}), bind: e.currentTarget.value },
                    })
                  }
                  radius="md"
                />
                <TextInput
                  label="Port"
                  placeholder="8080"
                  disabled={formDisabled}
                  value={config.management?.port || ""}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      management: { ...(config.management || {}), port: e.currentTarget.value },
                    })
                  }
                  radius="md"
                />
              </Group>
              <TextInput
                label="Management Domain / Host"
                placeholder="admin.example.com"
                description="If set, the management interface will only be accessible via this domain."
                disabled={formDisabled}
                value={(config.management?.allowedHosts || [])[0] || ""}
                onChange={(e) =>
                  setConfig({
                    ...config,
                    management: {
                      ...(config.management || {}),
                      allowedHosts: e.currentTarget.value ? [e.currentTarget.value] : [],
                    },
                  })
                }
                radius="md"
              />
              <TextInput
                label="Allowed IPs (comma-separated CIDRs)"
                placeholder="0.0.0.0/0, ::/0"
                disabled={formDisabled}
                value={(config.management?.allowedIps || []).join(", ")}
                onChange={(e) =>
                  setConfig({
                    ...config,
                    management: {
                      ...(config.management || {}),
                      allowedIps: e.currentTarget.value
                        .split(",")
                        .map((s) => s.trim())
                        .filter(Boolean),
                    },
                  })
                }
                radius="md"
              />
            </Stack>
          </Box>

          <Box>
            <Divider
              label={
                <Text size="xs" fw={800}>
                  LOGGING
                </Text>
              }
              labelPosition="left"
              mb="md"
            />
            <Group grow align="flex-end">
              <Select
                label="Log Level"
                disabled={formDisabled}
                data={[
                  { label: "Debug", value: "debug" },
                  { label: "Info", value: "info" },
                  { label: "Warn", value: "warn" },
                  { label: "Error", value: "error" },
                ]}
                value={config.log?.level || "info"}
                onChange={(v) =>
                  setConfig({
                    ...config,
                    log: { ...(config.log || {}), level: v || "info" },
                  })
                }
                radius="md"
              />
              <Select
                label="Log Format"
                disabled={formDisabled}
                data={[
                  { label: "Text (Console)", value: "text" },
                  { label: "JSON", value: "json" },
                ]}
                value={config.log?.format || "text"}
                onChange={(v) =>
                  setConfig({
                    ...config,
                    log: {
                      ...(config.log || {}),
                      format: (v as "json" | "text") || "text",
                    },
                  })
                }
                radius="md"
              />
              <Switch
                label="Development Mode"
                checked={config.log?.development || false}
                disabled={formDisabled}
                onChange={(e) =>
                  setConfig({
                    ...config,
                    log: {
                      ...(config.log || {}),
                      development: e.currentTarget.checked,
                    },
                  })
                }
                mb="xs"
              />
              <NumberInput
                label="Path metrics retention (days)"
                description="Aggregated path metrics"
                disabled={formDisabled}
                min={1}
                max={365}
                value={config.log?.pathStatsRetentionDays ?? 7}
                onChange={(v) =>
                  setConfig({
                    ...config,
                    log: {
                      ...(config.log || {}),
                      pathStatsRetentionDays: typeof v === 'number' ? v : 7,
                    },
                  })
                }
                radius="md"
              />
              <NumberInput
                label="Access log retention (days)"
                description="Detailed request traces"
                disabled={formDisabled}
                min={1}
                max={365}
                value={config.log?.accessLogRetentionDays ?? 7}
                onChange={(v) =>
                  setConfig({
                    ...config,
                    log: {
                      ...(config.log || {}),
                      accessLogRetentionDays: typeof v === 'number' ? v : 7,
                    },
                  })
                }
                radius="md"
              />
              <NumberInput
                label="Security threats retention (days)"
                description="WAF and anomaly logs"
                disabled={formDisabled}
                min={1}
                max={365}
                value={config.log?.securityThreatRetentionDays ?? 30}
                onChange={(v) =>
                  setConfig({
                    ...config,
                    log: {
                      ...(config.log || {}),
                      securityThreatRetentionDays: typeof v === 'number' ? v : 30,
                    },
                  })
                }
                radius="md"
              />
              <NumberInput
                label="Audit log retention (days)"
                description="System changes and login logs"
                disabled={formDisabled}
                min={1}
                max={365}
                value={config.log?.auditLogRetentionDays ?? 90}
                onChange={(v) =>
                  setConfig({
                    ...config,
                    log: {
                      ...(config.log || {}),
                      auditLogRetentionDays: typeof v === 'number' ? v : 90,
                    },
                  })
                }
                radius="md"
              />
            </Group>
          </Box>

          <Box>
            <Divider
              label={
                <Text size="xs" fw={800}>
                  SECURITY (PASETO + Database)
                </Text>
              }
              labelPosition="left"
              mb="md"
            />
            <Stack gap="md">
              <Switch
                label="Enable Role-Based Access Control (PASETO)"
                checked={config?.auth?.enabled || false}
                disabled={formDisabled}
                onChange={(e) =>
                  setConfig({
                    ...config,
                    auth: {
                      ...(config?.auth || {}),
                      enabled: e.currentTarget.checked,
                    },
                  })
                }
              />
              {config?.auth?.enabled && (
                <Stack gap="md">
                  <TextInput
                    label="PASETO Symmetric Key"
                    placeholder="32 characters minimum"
                    disabled={formDisabled}
                    value={config?.auth?.pasetoSecret || ""}
                    onChange={(e) =>
                      setConfig({
                        ...config,
                        auth: {
                          ...(config?.auth || {}),
                          pasetoSecret: e.currentTarget.value,
                        },
                      })
                    }
                    radius="md"
                    type="password"
                    rightSection={
                      <Tooltip label="Generate">
                        <ActionIcon
                          variant="subtle"
                          onClick={() =>
                            setConfig({
                              ...config,
                              auth: {
                                ...(config?.auth || {}),
                                pasetoSecret: generateRandomString(32),
                              },
                            })
                          }
                          disabled={formDisabled}
                        >
                          <IconRefresh size="1.1rem" />
                        </ActionIcon>
                      </Tooltip>
                    }
                  />
                  <Box>
                    <Text size="sm" fw={600} mb="xs">
                      Database
                    </Text>
                    <Select
                      label="Driver"
                      placeholder="Select database"
                      data={[
                        { value: "sqlite", label: "SQLite" },
                        { value: "postgres", label: "PostgreSQL" },
                        { value: "mysql", label: "MySQL" },
                        { value: "mariadb", label: "MariaDB" },
                      ]}
                      value={
                        config?.auth?.databaseConfig?.driver ||
                        inferDriver(
                          config?.auth?.databaseUrl,
                          config?.auth?.sqlitePath
                        )
                      }
                      onChange={(v) =>
                        setConfig({
                          ...config,
                          auth: {
                            ...(config?.auth || {}),
                            databaseConfig: {
                              ...(config?.auth?.databaseConfig || {}),
                              driver: (v as DatabaseConfig["driver"]) || "sqlite",
                              host: v && v !== "sqlite" ? config?.auth?.databaseConfig?.host || "127.0.0.1" : undefined,
                              port: v === "postgres" ? 5432 : v === "mysql" || v === "mariadb" ? 3306 : undefined,
                              database: v && v !== "sqlite" ? config?.auth?.databaseConfig?.database || "gateon" : undefined,
                              sslMode: v === "postgres" ? "disable" : undefined,
                            },
                            databaseUrl: undefined,
                            sqlitePath: undefined,
                          },
                        })
                      }
                      disabled={formDisabled}
                      radius="md"
                      mb="md"
                    />
                    {(config?.auth?.databaseConfig?.driver === "sqlite" ||
                      !config?.auth?.databaseConfig?.driver) && (
                      <TextInput
                        label="SQLite path"
                        placeholder="gateon.db"
                        disabled={formDisabled}
                        value={
                          config?.auth?.databaseConfig?.sqlitePath ??
                          config?.auth?.sqlitePath ??
                          (config?.auth?.databaseUrl &&
                          !config.auth.databaseUrl.includes("://")
                            ? config.auth.databaseUrl
                            : "")
                        }
                        onChange={(e) =>
                          setConfig({
                            ...config,
                            auth: {
                              ...(config?.auth || {}),
                              databaseConfig: {
                                ...(config?.auth?.databaseConfig || {}),
                                driver: "sqlite",
                                sqlitePath: e.currentTarget.value || "gateon.db",
                              },
                              databaseUrl: undefined,
                              sqlitePath: undefined,
                            },
                          })
                        }
                        radius="md"
                      />
                    )}
                    {(config?.auth?.databaseConfig?.driver === "postgres" ||
                      config?.auth?.databaseConfig?.driver === "mysql" ||
                      config?.auth?.databaseConfig?.driver === "mariadb") && (
                      <Stack gap="md">
                        <TextInput
                          label="Host"
                          placeholder="127.0.0.1"
                          disabled={formDisabled}
                          value={config?.auth?.databaseConfig?.host || ""}
                          onChange={(e) =>
                            setConfig({
                              ...config,
                              auth: {
                                ...(config?.auth || {}),
                                databaseConfig: {
                                  ...(config?.auth?.databaseConfig || {}),
                                  host: e.currentTarget.value,
                                },
                              },
                            })
                          }
                          radius="md"
                        />
                        <NumberInput
                          label="Port"
                          placeholder={
                            config?.auth?.databaseConfig?.driver === "postgres"
                              ? "5432"
                              : "3306"
                          }
                          min={1}
                          max={65535}
                          disabled={formDisabled}
                          value={
                            config?.auth?.databaseConfig?.port ||
                            (config?.auth?.databaseConfig?.driver === "postgres"
                              ? 5432
                              : 3306)
                          }
                          onChange={(v) =>
                            setConfig({
                              ...config,
                              auth: {
                                ...(config?.auth || {}),
                                databaseConfig: {
                                  ...(config?.auth?.databaseConfig || {}),
                                  port: typeof v === "string" ? parseInt(v, 10) || 0 : v ?? 0,
                                },
                              },
                            })
                          }
                          radius="md"
                        />
                        <TextInput
                          label="User"
                          placeholder="gateon"
                          disabled={formDisabled}
                          value={config?.auth?.databaseConfig?.user || ""}
                          onChange={(e) =>
                            setConfig({
                              ...config,
                              auth: {
                                ...(config?.auth || {}),
                                databaseConfig: {
                                  ...(config?.auth?.databaseConfig || {}),
                                  user: e.currentTarget.value,
                                },
                              },
                            })
                          }
                          radius="md"
                        />
                        <TextInput
                          label="Password"
                          type="password"
                          placeholder="••••••••"
                          disabled={formDisabled}
                          value={config?.auth?.databaseConfig?.password || ""}
                          onChange={(e) =>
                            setConfig({
                              ...config,
                              auth: {
                                ...(config?.auth || {}),
                                databaseConfig: {
                                  ...(config?.auth?.databaseConfig || {}),
                                  password: e.currentTarget.value,
                                },
                              },
                            })
                          }
                          radius="md"
                          rightSection={
                            <Tooltip label="Generate">
                              <ActionIcon
                                variant="subtle"
                                onClick={() =>
                                  setConfig({
                                    ...config,
                                    auth: {
                                      ...(config?.auth || {}),
                                      databaseConfig: {
                                        ...(config?.auth?.databaseConfig || {}),
                                        password: generateRandomString(24),
                                      },
                                    },
                                  })
                                }
                                disabled={formDisabled}
                              >
                                <IconRefresh size="1.1rem" />
                              </ActionIcon>
                            </Tooltip>
                          }
                        />
                        <TextInput
                          label="Database"
                          placeholder="gateon"
                          disabled={formDisabled}
                          value={config?.auth?.databaseConfig?.database || ""}
                          onChange={(e) =>
                            setConfig({
                              ...config,
                              auth: {
                                ...(config?.auth || {}),
                                databaseConfig: {
                                  ...(config?.auth?.databaseConfig || {}),
                                  database: e.currentTarget.value,
                                },
                              },
                            })
                          }
                          radius="md"
                        />
                        {config?.auth?.databaseConfig?.driver === "postgres" && (
                          <Select
                            label="SSL mode"
                            data={[
                              { value: "disable", label: "disable" },
                              { value: "require", label: "require" },
                              { value: "verify-ca", label: "verify-ca" },
                              { value: "verify-full", label: "verify-full" },
                            ]}
                            value={config?.auth?.databaseConfig?.sslMode || "disable"}
                            onChange={(v) =>
                              setConfig({
                                ...config,
                                auth: {
                                  ...(config?.auth || {}),
                                  databaseConfig: {
                                    ...(config?.auth?.databaseConfig || {}),
                                    sslMode: v || "disable",
                                  },
                                },
                              })
                            }
                            disabled={formDisabled}
                            radius="md"
                          />
                        )}
                      </Stack>
                    )}
                  </Box>
                  <Alert
                    icon={<IconInfoCircle size={16} />}
                    color="blue"
                    variant="light"
                    radius="md"
                  >
                    Sensitive values (database URL, password) are encrypted in
                    global.json when GATEON_ENCRYPTION_KEY is set. Changing the
                    secret key invalidates all sessions.
                  </Alert>
                </Stack>
              )}
            </Stack>
          </Box>

          {canEditGlobal && (
            <Group justify="flex-end" mt="md">
              <Button
                onClick={saveGatewayConfig}
                loading={saving}
                radius="md"
                px="xl"
              >
                Save Gateway Config
              </Button>
            </Group>
          )}
          {error && (
            <Text c="red" size="sm" fw={600}>
              {error}
            </Text>
          )}
          {savedOk && (
            <Text c="green" size="sm" fw={600}>
              Configuration successfully updated!
            </Text>
          )}
        </Stack>
      </Card>

      <Card withBorder padding="xl" radius="lg" shadow="xs">
        <Stack gap="lg">
          <Group gap="md">
            <Paper p="xs" radius="md" bg="orange.6">
              <IconBolt size={20} color="white" />
            </Paper>
            <div>
              <Title order={4} fw={700}>
                Performance & High-Throughput
              </Title>
              <Text c="dimmed" size="xs">
                Environment variables for 100k+ req/s. Set before starting the gateway.
              </Text>
            </div>
          </Group>
          <Alert icon={<IconInfoCircle size={16} />} color="orange" variant="light" radius="md">
            These are process-level env vars. Configure before starting Gateon or via your deployment (Docker, Kubernetes, systemd).
          </Alert>
          <Stack gap="sm">
            <Box>
              <Text size="sm" fw={600} mb={4}>Entrypoint Rate Limit</Text>
              <Text size="xs" c="dimmed" mb={4}>
                Per-IP requests/sec. Use <Code>0</Code> to disable for high throughput.
              </Text>
              <Group gap="xs">
                <Code block style={{ flex: 1 }}>GATEON_ENTRYPOINT_RATE_LIMIT_QPS=0</Code>
                <CopyButton value="GATEON_ENTRYPOINT_RATE_LIMIT_QPS=0">
                  {({ copied, copy }) => (
                    <Tooltip label={copied ? "Copied" : "Copy"}>
                      <ActionIcon color={copied ? "teal" : "gray"} variant="subtle" onClick={copy}>
                        {copied ? <IconCheck size={16} /> : <IconCopy size={16} />}
                      </ActionIcon>
                    </Tooltip>
                  )}
                </CopyButton>
              </Group>
            </Box>
            <Box>
              <Text size="sm" fw={600} mb={4}>Access Log Sampling</Text>
              <Text size="xs" c="dimmed" mb={4}>
                Log 1 in N requests. Use <Code>1000</Code> or <Code>10000</Code> for high traffic.
              </Text>
              <Group gap="xs">
                <Code block style={{ flex: 1 }}>GATEON_ACCESS_LOG_SAMPLE_RATE=1000</Code>
                <CopyButton value="GATEON_ACCESS_LOG_SAMPLE_RATE=1000">
                  {({ copied, copy }) => (
                    <Tooltip label={copied ? "Copied" : "Copy"}>
                      <ActionIcon color={copied ? "teal" : "gray"} variant="subtle" onClick={copy}>
                        {copied ? <IconCheck size={16} /> : <IconCopy size={16} />}
                      </ActionIcon>
                    </Tooltip>
                  )}
                </CopyButton>
              </Group>
            </Box>
          </Stack>
        </Stack>
      </Card>

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

      <Card withBorder shadow="sm" radius="md">
        <Stack gap="md">
          <Group justify="space-between">
            <Group gap="xs">
              <IconShieldLock color="var(--mantine-color-blue-filled)" />
              <Title order={3}>Global WAF Settings</Title>
            </Group>
            <Switch
              label="Protect all routes"
              checked={config.waf?.enabled || false}
              onChange={(e) =>
                setConfig({
                  ...config,
                  waf: {
                    ...(config.waf || {
                      useCrs: true,
                      paranoiaLevel: 1,
                    }),
                    enabled: e.currentTarget.checked,
                  },
                })
              }
              disabled={formDisabled}
            />
          </Group>
          <Text size="sm" c="dimmed">
            When enabled, the Web Application Firewall (OWASP Core Rule Set plus
            malware &amp; ransomware detection) runs on <strong>every</strong>{" "}
            route automatically — no per-route WAF middleware required. Changes
            apply live to existing routes.
          </Text>

          {config.waf?.enabled && (
            <Stack gap="sm">
              <Group grow>
                <Switch
                  label="Use OWASP Core Rule Set (CRS)"
                  checked={config.waf.useCrs}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      waf: {
                        ...config.waf!,
                        useCrs: e.currentTarget.checked,
                      },
                    })
                  }
                  disabled={formDisabled}
                />
                <Switch
                  label="Trust Cloudflare IPs/Headers"
                  checked={config.waf.trustCloudflareHeaders}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      waf: {
                        ...config.waf!,
                        trustCloudflareHeaders: e.currentTarget.checked,
                      },
                    })
                  }
                  disabled={formDisabled}
                />
                <Select
                  label="Paranoia Level"
                  data={[
                    { value: "1", label: "1 - Standard" },
                    { value: "2", label: "2 - High" },
                    { value: "3", label: "3 - Extreme" },
                    { value: "4", label: "4 - Insane" },
                  ]}
                  value={config.waf.paranoiaLevel.toString()}
                  onChange={(v) =>
                    setConfig({
                      ...config,
                      waf: {
                        ...config.waf!,
                        paranoiaLevel: parseInt(v || "1"),
                      },
                    })
                  }
                  disabled={formDisabled || !config.waf.useCrs}
                />
              </Group>

              {config.waf.useCrs && (
                <>
                  <Divider label="Global Protection Categories" labelPosition="center" />
                  <Group grow align="flex-start">
                    <Stack gap="xs">
                      <Switch
                        label="SQL Injection"
                        checked={config.waf.sqli !== false}
                        onChange={(e) => setConfig({ ...config, waf: { ...config.waf!, sqli: e.currentTarget.checked } })}
                        disabled={formDisabled}
                      />
                      <Switch
                        label="Cross-Site Scripting"
                        checked={config.waf.xss !== false}
                        onChange={(e) => setConfig({ ...config, waf: { ...config.waf!, xss: e.currentTarget.checked } })}
                        disabled={formDisabled}
                      />
                      <Switch
                        label="File Inclusion"
                        checked={config.waf.lfi !== false}
                        onChange={(e) => setConfig({ ...config, waf: { ...config.waf!, lfi: e.currentTarget.checked } })}
                        disabled={formDisabled}
                      />
                      <Switch
                        label="Code Execution"
                        checked={config.waf.rce !== false}
                        onChange={(e) => setConfig({ ...config, waf: { ...config.waf!, rce: e.currentTarget.checked } })}
                        disabled={formDisabled}
                      />
                    </Stack>
                    <Stack gap="xs">
                      <Switch
                        label="Scanner Detection"
                        checked={config.waf.scanner !== false}
                        onChange={(e) => setConfig({ ...config, waf: { ...config.waf!, scanner: e.currentTarget.checked } })}
                        disabled={formDisabled}
                      />
                      <Switch
                        label="Protocol Enforcement"
                        checked={config.waf.protocol !== false}
                        onChange={(e) => setConfig({ ...config, waf: { ...config.waf!, protocol: e.currentTarget.checked } })}
                        disabled={formDisabled}
                      />
                      <Switch
                        label="PHP Protection"
                        checked={config.waf.php !== false}
                        onChange={(e) => setConfig({ ...config, waf: { ...config.waf!, php: e.currentTarget.checked } })}
                        disabled={formDisabled}
                      />
                      <Switch
                        label="NodeJS Protection"
                        checked={config.waf.nodejs}
                        onChange={(e) => setConfig({ ...config, waf: { ...config.waf!, nodejs: e.currentTarget.checked } })}
                        disabled={formDisabled}
                      />
                    </Stack>
                    <Stack gap="xs">
                      <Switch
                        label="Java Protection"
                        checked={config.waf.java !== false}
                        onChange={(e) => setConfig({ ...config, waf: { ...config.waf!, java: e.currentTarget.checked } })}
                        disabled={formDisabled}
                      />
                      <Switch
                        label="WordPress Protection"
                        checked={config.waf.wordpress}
                        onChange={(e) => setConfig({ ...config, waf: { ...config.waf!, wordpress: e.currentTarget.checked } })}
                        disabled={formDisabled}
                      />
                      {config.waf.wordpress && (
                        <TagsInput
                          label="Allowed Admin IPs"
                          description="IPs allowed to access /wp-admin and /wp-login.php"
                          placeholder="1.2.3.4, 5.6.7.8"
                          value={config.waf.allowedAdminIps || []}
                          onChange={(v) => setConfig({ ...config, waf: { ...config.waf!, allowedAdminIps: v } })}
                          disabled={formDisabled}
                        />
                      )}
                      <Switch
                        label="IP Reputation"
                        checked={config.waf.ipReputation}
                        onChange={(e) => setConfig({ ...config, waf: { ...config.waf!, ipReputation: e.currentTarget.checked } })}
                        disabled={formDisabled}
                      />
                      <Switch
                        label="DOS Protection"
                        checked={config.waf.dosProtection}
                        onChange={(e) => setConfig({ ...config, waf: { ...config.waf!, dosProtection: e.currentTarget.checked } })}
                        disabled={formDisabled}
                      />
                    </Stack>
                    <Stack gap="xs">
                      <Switch
                        label="Malware Detection"
                        checked={config.waf.malwareDetection}
                        onChange={(e) => setConfig({ ...config, waf: { ...config.waf!, malwareDetection: e.currentTarget.checked } })}
                        disabled={formDisabled}
                      />
                      <Switch
                        label="Ransomware Detection"
                        checked={config.waf.ransomwareDetection}
                        onChange={(e) => setConfig({ ...config, waf: { ...config.waf!, ransomwareDetection: e.currentTarget.checked } })}
                        disabled={formDisabled}
                      />
                      <Switch
                        label="Data Loss Prevention (DLP)"
                        checked={config.waf.dlp}
                        onChange={(e) => setConfig({ ...config, waf: { ...config.waf!, dlp: e.currentTarget.checked } })}
                        disabled={formDisabled}
                      />
                    </Stack>
                  </Group>

                  {config.waf.dlp && (
                    <Select
                      label="When a leak is found"
                      description="Roll out in stages: watch first, then redact, then block once the false-positive rate is known. Applies to data-leak rules only."
                      data={[
                        { value: "block", label: "Block — refuse the whole response (default)" },
                        { value: "redact", label: "Redact — remove the finding, send the rest" },
                        { value: "audit", label: "Audit — record it, send the response untouched" },
                      ]}
                      value={config.waf.dlpAction || "block"}
                      onChange={(value) => setConfig({ ...config, waf: { ...config.waf!, dlpAction: value || "block" } })}
                      allowDeselect={false}
                      disabled={formDisabled}
                    />
                  )}

                  <NumberInput
                    label="Global Anomaly Threshold"
                    description="Default score required to block if not specified on route. Default: 5"
                    value={config.waf.anomalyThreshold || 5}
                    onChange={(v) => setConfig({ ...config, waf: { ...config.waf!, anomalyThreshold: parseInt(v?.toString() || "5") } })}
                    min={1}
                    disabled={formDisabled}
                  />

                  <Divider label="Application Tuning" labelPosition="center" />
                  <TagsInput
                    label="Gateway Origins"
                    description="The hostnames this gateway answers on. Used to tell a redirect or fetch
                      destination on this site from one somewhere else. Leave empty to use the Host()
                      rules from your routes — set it when a route matches on a path alone, or when the
                      gateway is reached by a name no route mentions. Without any origin, open-redirect
                      and SSRF checks have nothing to compare against and stay silent."
                    placeholder="app.example.com"
                    value={config.waf.origins ?? []}
                    onChange={(v) => setConfig({ ...config, waf: { ...config.waf!, origins: v } })}
                    disabled={formDisabled}
                    clearable
                  />
                  <MultiSelect
                    label="Platform Profiles"
                    description="Platforms running behind this gateway. Each one suppresses the specific
                      false positives that platform generates against itself — a WordPress comment field
                      really does contain PHP, and an issue tracker really does quote SQL. Exceptions are
                      scoped to a named rule on a named path and field; nothing is turned off globally."
                    placeholder={
                      (config.waf.appProfiles?.length ?? 0) > 0 ? undefined : "None — the default ruleset, untuned"
                    }
                    data={WAF_APP_PROFILES}
                    value={config.waf.appProfiles ?? []}
                    onChange={(v) => setConfig({ ...config, waf: { ...config.waf!, appProfiles: v } })}
                    disabled={formDisabled}
                    clearable
                    searchable
                  />
                  <Switch
                    label="SSRF Parameter Protection"
                    description="Block an off-origin URL in a parameter the server itself fetches (url,
                      webhook, feed, callback). Leave this off if the application accepts user-supplied
                      URLs by design — registering a webhook or importing an avatar is the same request
                      shape as the attack. Redirecting a user off-origin is always blocked and needs no
                      setting."
                    checked={config.waf.ssrfProtection}
                    onChange={(e) => setConfig({ ...config, waf: { ...config.waf!, ssrfProtection: e.currentTarget.checked } })}
                    disabled={formDisabled}
                  />

                  <Divider label="WAF Rules Management" labelPosition="center" />
                  <Group grow align="flex-start">
                    <Stack gap="xs">
                      <Switch
                        label="Auto Update Rules"
                        description="Periodically check for CRS updates"
                        checked={config.waf.autoUpdateRules}
                        onChange={(e) => setConfig({ ...config, waf: { ...config.waf!, autoUpdateRules: e.currentTarget.checked } })}
                        disabled={formDisabled}
                      />
                    </Stack>
                    <Stack gap="xs">
                      <NumberInput
                        label="Update Interval (hours)"
                        value={config.waf.updateIntervalHours || 24}
                        onChange={(v) => setConfig({ ...config, waf: { ...config.waf!, updateIntervalHours: parseInt(v?.toString() || "24") } })}
                        min={1}
                        disabled={formDisabled || !config.waf.autoUpdateRules}
                      />
                    </Stack>
                  </Group>
                  <TextInput
                    label="Rules Source URL"
                    description="URL to CRS rules ZIP (leave empty for default)"
                    placeholder="https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.0.0.zip"
                    value={config.waf.rulesUrl || ""}
                    onChange={(e) => setConfig({ ...config, waf: { ...config.waf!, rulesUrl: e.currentTarget.value } })}
                    disabled={formDisabled || !config.waf.autoUpdateRules}
                  />

                  <Divider label="ClamAV Anti-Malware" labelPosition="center" />
                  {config.waf?.malwareDetection && status && !status.clamavInstalled && (
                    <Alert icon={<IconInfoCircle size="1rem" />} title="ClamAV Not Detected" color="red">
                      <Stack gap="xs">
                        <Text size="sm">
                          Malware detection is enabled, but ClamAV is not installed or not running on the server.
                          Please ensure ClamAV is installed locally or via Docker as configured below.
                        </Text>
                        <Group gap="sm">
                          <Menu shadow="md" width={200} position="bottom-start">
                            <Menu.Target>
                              <Button 
                                variant="white" 
                                size="xs" 
                                leftSection={installing ? <Loader size={14} color="blue" /> : <IconDownload size={14} />}
                                rightSection={<IconChevronDown size={14} />}
                                disabled={installing}
                              >
                                Install Now
                              </Button>
                            </Menu.Target>

                            <Menu.Dropdown>
                              <Menu.Label>Choose Installation Mode</Menu.Label>
                              <Menu.Item 
                                leftSection={<IconAdjustments size={14} />} 
                                onClick={() => handleInstall(1)}
                              >
                                Local Installation
                              </Menu.Item>
                              <Menu.Item 
                                leftSection={<IconBox size={14} />} 
                                onClick={() => handleInstall(2)}
                              >
                                Docker Container
                              </Menu.Item>
                            </Menu.Dropdown>
                          </Menu>
                        </Group>
                      </Stack>
                    </Alert>
                  )}
                  {status && status.clamavInstalled && (
                    <Alert icon={<IconShieldCheck size="1rem" />} title="ClamAV Installed" color="green">
                      <Group justify="space-between" align="center">
                        <Text size="sm">
                          ClamAV is installed and managed by Gateon. You can remove it if it is no longer needed.
                        </Text>
                        <Button
                          variant="white"
                          color="red"
                          size="xs"
                          leftSection={uninstalling ? <Loader size={14} color="red" /> : <IconTrash size={14} />}
                          disabled={uninstalling || formDisabled}
                          onClick={handleUninstall}
                        >
                          Uninstall
                        </Button>
                      </Group>
                    </Alert>
                  )}
                  <Group grow>
                    <Select
                      label="Installation Mode"
                      data={[
                        { value: '1', label: 'Local Installation' },
                        { value: '2', label: 'Docker Container' },
                      ]}
                      value={config.waf.clamav?.installationMode?.toString() || '2'}
                      onChange={(val) => setConfig({
                        ...config,
                        waf: {
                          ...config.waf!,
                          clamav: {
                            ...(config.waf!.clamav || {}),
                            installationMode: parseInt(val || '2')
                          }
                        }
                      })}
                      disabled={formDisabled || !config.waf.malwareDetection}
                    />
                    <Switch
                      label="Auto-Install/Manage"
                      description="Let Gateon handle installation and lifecycle"
                      checked={config.waf.clamav?.autoInstall}
                      onChange={(e) => setConfig({
                        ...config,
                        waf: {
                          ...config.waf!,
                          clamav: {
                            ...(config.waf!.clamav || {}),
                            autoInstall: e.currentTarget.checked
                          }
                        }
                      })}
                      disabled={formDisabled || !config.waf.malwareDetection}
                      mt="xl"
                    />
                  </Group>

                  <Group grow>
                    <TextInput
                      label="ClamAV Address"
                      description="Address of ClamAV daemon"
                      placeholder="tcp://localhost:3310"
                      value={config.waf.clamav?.clamavAddr || config.waf.clamavAddr || ""}
                      onChange={(e) => setConfig({
                        ...config,
                        waf: {
                          ...config.waf!,
                          clamav: {
                            ...(config.waf!.clamav || {}),
                            clamavAddr: e.currentTarget.value
                          }
                        }
                      })}
                      disabled={formDisabled || !config.waf.malwareDetection}
                    />
                    <TextInput
                      label="Full Scan Schedule"
                      description="Cron expression for full system scans"
                      placeholder="0 2 * * *"
                      value={config.waf.clamav?.fullScanSchedule || ""}
                      onChange={(e) => setConfig({
                        ...config,
                        waf: {
                          ...config.waf!,
                          clamav: {
                            ...(config.waf!.clamav || {}),
                            fullScanSchedule: e.currentTarget.value
                          }
                        }
                      })}
                      disabled={formDisabled || !config.waf.malwareDetection}
                    />
                  </Group>

                  <Group grow>
                    <Switch
                      label="Low Resource Mode"
                      description="Optimize for 1GB RAM / 2 Cores"
                      checked={config.waf.clamav?.lowResourceMode}
                      onChange={(e) => setConfig({
                        ...config,
                        waf: {
                          ...config.waf!,
                          clamav: {
                            ...(config.waf!.clamav || {}),
                            lowResourceMode: e.currentTarget.checked
                          }
                        }
                      })}
                      disabled={formDisabled || !config.waf.malwareDetection}
                    />
                    {config.waf.clamav?.installationMode === 2 && (
                      <TextInput
                        label="Docker Image"
                        value={config.waf.clamav?.dockerImage || ""}
                        placeholder="clamav/clamav:latest"
                        onChange={(e) => setConfig({
                          ...config,
                          waf: {
                            ...config.waf!,
                            clamav: {
                              ...(config.waf!.clamav || {}),
                              dockerImage: e.currentTarget.value
                            }
                          }
                        })}
                        disabled={formDisabled || !config.waf.malwareDetection}
                      />
                    )}
                  </Group>

                  <Button
                    variant="light"
                    color="blue"
                    onClick={triggerWafUpdate}
                    loading={saving}
                    disabled={formDisabled}
                    mt="xs"
                  >
                    Update WAF Rules Now
                  </Button>

                  <Divider label="Global Bot Management" labelPosition="center" />
                  <Group grow>
                    <Switch
                      label="Enable Bot Management"
                      checked={config.waf.botManagement?.enabled}
                      onChange={(e) => setConfig({
                        ...config,
                        waf: {
                          ...config.waf!,
                          botManagement: {
                            ...(config.waf!.botManagement || {}),
                            enabled: e.currentTarget.checked
                          }
                        }
                      })}
                      disabled={formDisabled}
                    />
                    <Switch
                      label="Browser Integrity"
                      checked={config.waf.botManagement?.enableBrowserIntegrity}
                      onChange={(e) => setConfig({
                        ...config,
                        waf: {
                          ...config.waf!,
                          botManagement: {
                            ...(config.waf!.botManagement || {}),
                            enableBrowserIntegrity: e.currentTarget.checked
                          }
                        }
                      })}
                      disabled={formDisabled || !config.waf.botManagement?.enabled}
                    />
                    <Switch
                      label="JS Challenge"
                      checked={config.waf.botManagement?.enableJsChallenge}
                      onChange={(e) => setConfig({
                        ...config,
                        waf: {
                          ...config.waf!,
                          botManagement: {
                            ...(config.waf!.botManagement || {}),
                            enableJsChallenge: e.currentTarget.checked
                          }
                        }
                      })}
                      disabled={formDisabled || !config.waf.botManagement?.enabled}
                    />
                  </Group>
                </>
              )}

              <Textarea
                label="Custom Global Directives"
                description="Coraza/ModSecurity compatible directives applied globally."
                placeholder="SecRule ARGS 'foo' 'id:1,deny,status:403'"
                value={config.waf.customDirectives || ""}
                onChange={(e) =>
                  setConfig({
                    ...config,
                    waf: {
                      ...config.waf!,
                      customDirectives: e.currentTarget.value,
                    },
                  })
                }
                disabled={formDisabled}
                minRows={4}
                autosize
              />
              {canEditGlobal && (
                <Group justify="flex-end" mt="md">
                  <Button onClick={saveGatewayConfig} loading={saving} size="sm">
                    Save WAF Settings
                  </Button>
                </Group>
              )}
            </Stack>
          )}
        </Stack>
      </Card>

      <Card withBorder shadow="sm" radius="md">
        <Stack gap="md">
          <Group justify="space-between">
            <Group gap="xs">
              <IconServer color="var(--mantine-color-teal-filled)" />
              <Title order={3}>High Availability (VRRP)</Title>
            </Group>
            <Switch
              label="Enable HA"
              checked={config.ha?.enabled || false}
              onChange={(e) =>
                setConfig({
                  ...config,
                  ha: {
                    ...(config.ha || {
                      priority: 100,
                      virtualRouterId: 51,
                      advertInt: 1,
                    }),
                    enabled: e.currentTarget.checked,
                  },
                })
              }
              disabled={formDisabled}
            />
          </Group>
          <Text size="sm" c="dimmed">
            Configure Active-Passive failover using VRRP-like protocol. Requires VIP management permissions.
          </Text>

          {config.ha?.enabled && (
            <Stack gap="sm">
              <TextInput
                label="Network Interface"
                placeholder="eth0"
                value={config.ha.interface || ""}
                onChange={(e) => setConfig({...config, ha: {...config.ha!, interface: e.currentTarget.value}})}
                disabled={formDisabled}
              />
              <Group grow>
                <NumberInput
                  label="Virtual Router ID"
                  min={1}
                  max={255}
                  value={config.ha.virtualRouterId}
                  onChange={(v) => setConfig({...config, ha: {...config.ha!, virtualRouterId: Number(v)}})}
                  disabled={formDisabled}
                />
                <NumberInput
                  label="Priority"
                  min={1}
                  max={255}
                  value={config.ha.priority}
                  onChange={(v) => setConfig({...config, ha: {...config.ha!, priority: Number(v)}})}
                  disabled={formDisabled}
                />
              </Group>
              <TextInput
                label="Virtual IPs (comma-separated)"
                placeholder="192.168.1.100/24"
                value={(config.ha.virtualIps || []).join(", ")}
                onChange={(e) => setConfig({...config, ha: {...config.ha!, virtualIps: e.currentTarget.value.split(",").map(s => s.trim()).filter(Boolean)}})}
                disabled={formDisabled}
              />
              {canEditGlobal && (
                <Group justify="flex-end" mt="md">
                  <Button onClick={saveGatewayConfig} loading={saving} size="sm">
                    Save HA Settings
                  </Button>
                </Group>
              )}
            </Stack>
          )}
        </Stack>
      </Card>

      <Card withBorder shadow="sm" radius="md">
        <Stack gap="md">
          <Group justify="space-between">
            <Group gap="xs">
              <IconActivity color="var(--mantine-color-orange-filled)" />
              <Title order={3}>Anomaly Detection</Title>
            </Group>
            <Switch
              label="Enable AI Detection"
              checked={config.anomalyDetection?.enabled || false}
              onChange={(e) =>
                setConfig({
                  ...config,
                  anomalyDetection: {
                    ...(config.anomalyDetection || {
                      checkIntervalSeconds: 60,
                      sensitivity: 0.5,
                    }),
                    enabled: e.currentTarget.checked,
                  },
                })
              }
              disabled={formDisabled}
            />
          </Group>
          <Text size="sm" c="dimmed">
            Monitor traffic patterns in-process and detect anomalies in real-time.
          </Text>

          {config.anomalyDetection?.enabled && (
            <Stack gap="sm">
              <Group grow>
                <NumberInput
                  label="Check Interval (s)"
                  min={10}
                  value={config.anomalyDetection.checkIntervalSeconds}
                  onChange={(v) => setConfig({...config, anomalyDetection: {...config.anomalyDetection!, checkIntervalSeconds: Number(v)}})}
                  disabled={formDisabled}
                />
                <NumberInput
                  label="Sensitivity"
                  decimalScale={2}
                  step={0.1}
                  min={0}
                  max={1}
                  value={config.anomalyDetection.sensitivity}
                  onChange={(v) => setConfig({...config, anomalyDetection: {...config.anomalyDetection!, sensitivity: Number(v)}})}
                  disabled={formDisabled}
                />
                <NumberInput
                  label="Security Threat Threshold"
                  decimalScale={1}
                  step={1}
                  min={1}
                  max={100}
                  value={config.anomalyDetection.securityThreatThreshold || 15.0}
                  onChange={(v) => setConfig({...config, anomalyDetection: {...config.anomalyDetection!, securityThreatThreshold: Number(v)}})}
                  disabled={formDisabled}
                />
              </Group>
              {canEditGlobal && (
                <Group justify="flex-end" mt="md">
                  <Button onClick={saveGatewayConfig} loading={saving} size="sm">
                    Save Anomaly Settings
                  </Button>
                </Group>
              )}
            </Stack>
          )}
        </Stack>
      </Card>

      <Card withBorder shadow="sm" radius="md">
        <Stack gap="md">
          <Group justify="space-between">
            <Group gap="xs">
              <IconCpu color="var(--mantine-color-grape-filled)" />
              <Title order={3}>eBPF Offloading</Title>
            </Group>
            <Switch
              label="Enable eBPF"
              checked={config.ebpf?.enabled || false}
              onChange={(e) =>
                setConfig({
                  ...config,
                  ebpf: {
                    ...(config.ebpf || {}),
                    enabled: e.currentTarget.checked,
                  },
                })
              }
              disabled={formDisabled}
            />
          </Group>
          <Text size="sm" c="dimmed">
            Offload traffic processing to the Linux kernel for maximum performance.
          </Text>

          {config.ebpf?.enabled && (
            <Stack gap="sm">
              {netInfoError || !netInfo?.interfaces?.length ? (
                // Fallback to free-text when the host interface list is
                // unavailable (e.g. air-gapped or restricted environments).
                <TextInput
                  label="Network Interface"
                  description="The network interface to attach eBPF programs to (e.g. eth0)"
                  placeholder="eth0"
                  value={config.ebpf.interface || ""}
                  onChange={(e) => setConfig({...config, ebpf: {...config.ebpf!, interface: e.currentTarget.value}})}
                  disabled={formDisabled}
                />
              ) : (
                <Select
                  label="Network Interface"
                  description="The NIC to attach eBPF/XDP programs to. Pick the interface that carries your traffic."
                  placeholder={
                    netInfo.interfaces.find((i) => i.recommended)
                      ? `${netInfo.interfaces.find((i) => i.recommended)!.name} (recommended)`
                      : "Select interface"
                  }
                  data={netInfo.interfaces.map((i) => ({
                    value: i.name,
                    label: `${i.name}${i.recommended ? " ★" : ""} — ${
                      i.addrs.find((a) => a.includes(".")) || "no IPv4"
                    }${i.up ? "" : " (down)"}`,
                  }))}
                  value={config.ebpf.interface || null}
                  onChange={(val) => setConfig({...config, ebpf: {...config.ebpf!, interface: val || ""}})}
                  searchable
                  allowDeselect={false}
                  disabled={formDisabled}
                />
              )}
              {netInfo?.ebpf?.attached ? (
                netInfo.ebpf.attachMode === "generic" ? (
                  <Text size="xs" c="yellow">
                    <IconAlertTriangle size={12} style={{ verticalAlign: "middle" }} /> XDP attached to{" "}
                    {netInfo.ebpf.interface} in generic (SKB) mode — native driver mode is
                    unavailable on this NIC, so throughput is reduced. Drop metrics are live.
                  </Text>
                ) : (
                  <Text size="xs" c="teal">
                    <IconCheck size={12} style={{ verticalAlign: "middle" }} /> XDP attached to{" "}
                    {netInfo.ebpf.interface} (native mode); eBPF drop metrics are live.
                  </Text>
                )
              ) : netInfo?.ebpf?.enabled ? (
                <Alert color="red" variant="light" icon={<IconAlertTriangle size="1rem" />} title="XDP not attached">
                  <Text size="sm">
                    eBPF is enabled but the XDP program is not attached, so eBPF drop
                    metrics will read 0.
                    {netInfo.ebpf.loadError ? ` Reason: ${netInfo.ebpf.loadError}` : " Verify the selected interface exists and the gateway has CAP_NET_ADMIN."}
                  </Text>
                </Alert>
              ) : null}
              <Switch
                label="XDP Rate Limiting"
                description="Drop packets at the network driver level"
                checked={config.ebpf.xdpRateLimit || false}
                onChange={(e) => setConfig({...config, ebpf: {...config.ebpf!, xdpRateLimit: e.currentTarget.checked}})}
                disabled={formDisabled}
              />
              <Switch
                label="XDP IP Shunning"
                description="Automatically shun malicious IPs at the driver level (IPS)"
                checked={config.ebpf.xdpIpShunning || false}
                onChange={(e) => setConfig({...config, ebpf: {...config.ebpf!, xdpIpShunning: e.currentTarget.checked}})}
                disabled={formDisabled}
              />
              <Switch
                label="TC Filtering"
                description="Kernel-level traffic classification and filtering"
                checked={config.ebpf.tcFiltering || false}
                onChange={(e) => setConfig({...config, ebpf: {...config.ebpf!, tcFiltering: e.currentTarget.checked}})}
                disabled={formDisabled}
              />
              <Divider label="Port Knocking" labelPosition="left" />
              <Switch
                label="Enable Port Knocking"
                description="Hide management port until a secret sequence of knocks is received (XDP)."
                checked={config.ebpf.enableKnocking || false}
                onChange={(e) => setConfig({...config, ebpf: {...config.ebpf!, enableKnocking: e.currentTarget.checked}})}
                disabled={formDisabled}
              />
              {config.ebpf.enableKnocking && (
                <>
                  <NumberInput
                    label="Management Port to Hide"
                    placeholder="8080"
                    value={config.ebpf.mgmtPort || 8080}
                    onChange={(val) => setConfig({...config, ebpf: {...config.ebpf!, mgmtPort: Number(val)}})}
                    disabled={formDisabled}
                  />
                  <TagsInput
                    label="Knocking Sequence (Ports)"
                    description="The sequence of ports to knock (e.g. 7000, 8000, 9000)."
                    placeholder="7000, 8000, 9000"
                    value={(config.ebpf.knockingSequence || []).map(String)}
                    onChange={(val) => setConfig({...config, ebpf: {...config.ebpf!, knockingSequence: val.map(Number)}})}
                    disabled={formDisabled}
                  />
                </>
              )}
              {canEditGlobal && (
                <Group justify="flex-end" mt="md">
                  <Button onClick={saveGatewayConfig} loading={saving} size="sm">
                    Save eBPF Settings
                  </Button>
                </Group>
              )}
            </Stack>
          )}
        </Stack>
      </Card>
      
      <GeoIPSettingsCard
        config={config.geoip || {}}
        onChange={(geoip) => setConfig({ ...config, geoip })}
        onSave={saveGatewayConfig}
        saving={saving}
        disabled={formDisabled}
      />

      <SecurityAdvancedSettingsCard
        config={config}
        onChange={setConfig}
        disabled={formDisabled}
      />

      <TitanSettingsCard
        config={config}
        onChange={setConfig}
        disabled={formDisabled}
      />

      <AlertingSettingsCard
        config={config}
        onChange={setConfig}
        disabled={formDisabled}
      />

      <AuditSettingsCard
        config={config}
        onChange={setConfig}
        disabled={formDisabled}
      />

      {canEditGlobal && (
        <Paper withBorder p="md" radius="md" style={{ position: 'sticky', bottom: 20, zIndex: 10, boxShadow: 'var(--mantine-shadow-lg)' }}>
          <Group justify="space-between">
            <div>
              <Text fw={600}>Unsaved Changes</Text>
              <Text size="xs" c="dimmed">You have modified the global configuration. Save to apply changes.</Text>
            </div>
            <Button onClick={saveGatewayConfig} loading={saving} leftSection={<IconCheck size={16} />}>
              Save Global Configuration
            </Button>
          </Group>
        </Paper>
      )}

      <AppearanceCard colorScheme={colorScheme} setColorScheme={setColorScheme} />
    </Stack>
  );
}
