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
} from "@tabler/icons-react";
import { ConfigImportExportCard } from "../components/ConfigImportExportCard";
import { GeneralSettingsCard } from "../components/settings/GeneralSettingsCard";
import { PresetsCard } from "../components/settings/PresetsCard";
import { AppearanceCard } from "../components/settings/AppearanceCard";
import { usePermissions } from "../hooks/usePermissions";
import { useAuthStore } from "../store/useAuthStore";
import { useApiConfigStore } from "../store/useApiConfigStore";
import type { GlobalConfig, DatabaseConfig } from "../types/gateon";
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
    management: { bind: "0.0.0.0", port: "8080", allowed_ips: ["0.0.0.0/0", "::/0"], host: "" },
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [savedOk, setSavedOk] = useState(false);
  const [generalSavedOk, setGeneralSavedOk] = useState(false);

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


  const tls = config.tls || { enabled: false };
  const redis = config.redis || { enabled: false };
  const otel = config.otel || { enabled: false };
  const transport = config.transport || {};

  const applyPreset = (preset: "development" | "production" | "high-throughput") => {
    const base = { ...config };
    if (preset === "development") {
      setConfig({
        ...base,
        log: { level: "debug", development: true, format: "text", path_stats_retention_days: 7 },
        tls: { ...tls, enabled: false },
        redis: { ...redis, enabled: false },
        otel: { ...otel, enabled: false },
      });
    } else if (preset === "production") {
      setConfig({
        ...base,
        log: { level: "info", development: false, format: "json", path_stats_retention_days: 30 },
        tls: { ...tls, enabled: true },
        redis: { ...redis, enabled: true },
        otel: { ...otel, enabled: true },
      });
    } else if (preset === "high-throughput") {
      setConfig({
        ...base,
        log: { level: "warn", development: false, format: "json", path_stats_retention_days: 7 },
        tls: tls,
        redis: redis,
        otel: otel,
        transport: {
          max_idle_conns: 20000,
          max_idle_conns_per_host: 2000,
          idle_conn_timeout_seconds: 90,
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
                        value={tls.acme.ca_server || ""}
                        onChange={(e) =>
                          setConfig({
                            ...config,
                            tls: {
                              ...tls,
                              acme: {
                                ...tls.acme!,
                                ca_server: e.currentTarget.value,
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
                        value={tls.acme.challenge_type || "http"}
                        onChange={(v) =>
                          setConfig({
                            ...config,
                            tls: {
                              ...tls,
                              acme: {
                                ...tls.acme!,
                                challenge_type: v || "http",
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
                      value={tls.min_tls_version || "TLS1.2"}
                      onChange={(val) =>
                        setConfig({
                          ...config,
                          tls: { ...tls, min_tls_version: val || "TLS1.2" },
                        })
                      }
                      radius="md"
                    />
                    <Select
                      label="Max TLS Version"
                      disabled={formDisabled}
                      data={["TLS1.2", "TLS1.3"]}
                      value={tls.max_tls_version || ""}
                      placeholder="Default"
                      onChange={(val) =>
                        setConfig({
                          ...config,
                          tls: { ...tls, max_tls_version: val || "" },
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
                    value={tls.client_auth_type || "NoClientCert"}
                    onChange={(val) =>
                      setConfig({
                        ...config,
                        tls: { ...tls, client_auth_type: val || "NoClientCert" },
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
                    value={tls.cipher_suites || []}
                    onChange={(val) =>
                      setConfig({
                        ...config,
                        tls: { ...tls, cipher_suites: val },
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
                value={transport.max_idle_conns || ""}
                onChange={(val) =>
                  setConfig({
                    ...config,
                    transport: {
                      ...transport,
                      max_idle_conns: val ? Number(val) : 0,
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
                value={transport.max_idle_conns_per_host || ""}
                onChange={(val) =>
                  setConfig({
                    ...config,
                    transport: {
                      ...transport,
                      max_idle_conns_per_host: val ? Number(val) : 0,
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
                value={transport.idle_conn_timeout_seconds || ""}
                onChange={(val) =>
                  setConfig({
                    ...config,
                    transport: {
                      ...transport,
                      idle_conn_timeout_seconds: val ? Number(val) : 0,
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
                  value={otel.service_name || ""}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      otel: { ...otel, service_name: e.currentTarget.value },
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
                value={config.management?.host || ""}
                onChange={(e) =>
                  setConfig({
                    ...config,
                    management: { ...(config.management || {}), host: e.currentTarget.value },
                  })
                }
                radius="md"
              />
              <TextInput
                label="Allowed IPs (comma-separated CIDRs)"
                placeholder="0.0.0.0/0, ::/0"
                disabled={formDisabled}
                value={(config.management?.allowed_ips || []).join(", ")}
                onChange={(e) =>
                  setConfig({
                    ...config,
                    management: {
                      ...(config.management || {}),
                      allowed_ips: e.currentTarget.value
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
                description="How long to keep aggregated path metrics in storage"
                disabled={formDisabled}
                min={1}
                max={365}
                value={config.log?.path_stats_retention_days ?? 7}
                onChange={(v) =>
                  setConfig({
                    ...config,
                    log: {
                      ...(config.log || {}),
                      path_stats_retention_days: typeof v === 'number' ? v : 7,
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
                    value={config?.auth?.paseto_secret || ""}
                    onChange={(e) =>
                      setConfig({
                        ...config,
                        auth: {
                          ...(config?.auth || {}),
                          paseto_secret: e.currentTarget.value,
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
                                paseto_secret: generateRandomString(32),
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
                    <Text size="sm" fw={600} mb="xs" required>
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
                        config?.auth?.database_config?.driver ||
                        inferDriver(
                          config?.auth?.database_url,
                          config?.auth?.sqlite_path
                        )
                      }
                      onChange={(v) =>
                        setConfig({
                          ...config,
                          auth: {
                            ...(config?.auth || {}),
                            database_config: {
                              ...(config?.auth?.database_config || {}),
                              driver: (v as DatabaseConfig["driver"]) || "sqlite",
                              host: v && v !== "sqlite" ? config?.auth?.database_config?.host || "127.0.0.1" : undefined,
                              port: v === "postgres" ? 5432 : v === "mysql" || v === "mariadb" ? 3306 : undefined,
                              database: v && v !== "sqlite" ? config?.auth?.database_config?.database || "gateon" : undefined,
                              ssl_mode: v === "postgres" ? "disable" : undefined,
                            },
                            database_url: undefined,
                            sqlite_path: undefined,
                          },
                        })
                      }
                      disabled={formDisabled}
                      radius="md"
                      mb="md"
                    />
                    {(config?.auth?.database_config?.driver === "sqlite" ||
                      !config?.auth?.database_config?.driver) && (
                      <TextInput
                        label="SQLite path"
                        placeholder="gateon.db"
                        disabled={formDisabled}
                        value={
                          config?.auth?.database_config?.sqlite_path ??
                          config?.auth?.sqlite_path ??
                          (config?.auth?.database_url &&
                          !config.auth.database_url.includes("://")
                            ? config.auth.database_url
                            : "")
                        }
                        onChange={(e) =>
                          setConfig({
                            ...config,
                            auth: {
                              ...(config?.auth || {}),
                              database_config: {
                                ...(config?.auth?.database_config || {}),
                                driver: "sqlite",
                                sqlite_path: e.currentTarget.value || "gateon.db",
                              },
                              database_url: undefined,
                              sqlite_path: undefined,
                            },
                          })
                        }
                        radius="md"
                      />
                    )}
                    {(config?.auth?.database_config?.driver === "postgres" ||
                      config?.auth?.database_config?.driver === "mysql" ||
                      config?.auth?.database_config?.driver === "mariadb") && (
                      <Stack gap="md">
                        <TextInput
                          label="Host"
                          placeholder="127.0.0.1"
                          disabled={formDisabled}
                          value={config?.auth?.database_config?.host || ""}
                          onChange={(e) =>
                            setConfig({
                              ...config,
                              auth: {
                                ...(config?.auth || {}),
                                database_config: {
                                  ...(config?.auth?.database_config || {}),
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
                            config?.auth?.database_config?.driver === "postgres"
                              ? "5432"
                              : "3306"
                          }
                          min={1}
                          max={65535}
                          disabled={formDisabled}
                          value={
                            config?.auth?.database_config?.port ||
                            (config?.auth?.database_config?.driver === "postgres"
                              ? 5432
                              : 3306)
                          }
                          onChange={(v) =>
                            setConfig({
                              ...config,
                              auth: {
                                ...(config?.auth || {}),
                                database_config: {
                                  ...(config?.auth?.database_config || {}),
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
                          value={config?.auth?.database_config?.user || ""}
                          onChange={(e) =>
                            setConfig({
                              ...config,
                              auth: {
                                ...(config?.auth || {}),
                                database_config: {
                                  ...(config?.auth?.database_config || {}),
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
                          value={config?.auth?.database_config?.password || ""}
                          onChange={(e) =>
                            setConfig({
                              ...config,
                              auth: {
                                ...(config?.auth || {}),
                                database_config: {
                                  ...(config?.auth?.database_config || {}),
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
                                      database_config: {
                                        ...(config?.auth?.database_config || {}),
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
                          value={config?.auth?.database_config?.database || ""}
                          onChange={(e) =>
                            setConfig({
                              ...config,
                              auth: {
                                ...(config?.auth || {}),
                                database_config: {
                                  ...(config?.auth?.database_config || {}),
                                  database: e.currentTarget.value,
                                },
                              },
                            })
                          }
                          radius="md"
                        />
                        {config?.auth?.database_config?.driver === "postgres" && (
                          <Select
                            label="SSL mode"
                            data={[
                              { value: "disable", label: "disable" },
                              { value: "require", label: "require" },
                              { value: "verify-ca", label: "verify-ca" },
                              { value: "verify-full", label: "verify-full" },
                            ]}
                            value={config?.auth?.database_config?.ssl_mode || "disable"}
                            onChange={(v) =>
                              setConfig({
                                ...config,
                                auth: {
                                  ...(config?.auth || {}),
                                  database_config: {
                                    ...(config?.auth?.database_config || {}),
                                    ssl_mode: v || "disable",
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
              label="Enable Global Rules"
              checked={config.waf?.enabled || false}
              onChange={(e) =>
                setConfig({
                  ...config,
                  waf: {
                    ...(config.waf || {
                      use_crs: true,
                      paranoia_level: 1,
                    }),
                    enabled: e.currentTarget.checked,
                  },
                })
              }
              disabled={formDisabled}
            />
          </Group>
          <Text size="sm" c="dimmed">
            Configure global Web Application Firewall rules that apply to all
            routes using the WAF middleware.
          </Text>

          {config.waf?.enabled && (
            <Stack gap="sm">
              <Group grow>
                <Switch
                  label="Use OWASP Core Rule Set (CRS)"
                  checked={config.waf.use_crs}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      waf: {
                        ...config.waf!,
                        use_crs: e.currentTarget.checked,
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
                  value={config.waf.paranoia_level.toString()}
                  onChange={(v) =>
                    setConfig({
                      ...config,
                      waf: {
                        ...config.waf!,
                        paranoia_level: parseInt(v || "1"),
                      },
                    })
                  }
                  disabled={formDisabled || !config.waf.use_crs}
                />
              </Group>

              {config.waf.use_crs && (
                <>
                  <Divider label="Global Protection Categories" labelPosition="center" />
                  <Group grow>
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
                        label="Java Protection"
                        checked={config.waf.java !== false}
                        onChange={(e) => setConfig({ ...config, waf: { ...config.waf!, java: e.currentTarget.checked } })}
                        disabled={formDisabled}
                      />
                    </Stack>
                  </Group>
                </>
              )}

              <Textarea
                label="Custom Global Directives"
                description="Coraza/ModSecurity compatible directives applied globally."
                placeholder="SecRule ARGS 'foo' 'id:1,deny,status:403'"
                value={config.waf.custom_directives || ""}
                onChange={(e) =>
                  setConfig({
                    ...config,
                    waf: {
                      ...config.waf!,
                      custom_directives: e.currentTarget.value,
                    },
                  })
                }
                disabled={formDisabled}
                minRows={4}
                autosize
              />
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
                      virtual_router_id: 51,
                      advert_int: 1,
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
                  value={config.ha.virtual_router_id}
                  onChange={(v) => setConfig({...config, ha: {...config.ha!, virtual_router_id: Number(v)}})}
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
                value={(config.ha.virtual_ips || []).join(", ")}
                onChange={(e) => setConfig({...config, ha: {...config.ha!, virtual_ips: e.currentTarget.value.split(",").map(s => s.trim()).filter(Boolean)}})}
                disabled={formDisabled}
              />
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
              checked={config.anomaly_detection?.enabled || false}
              onChange={(e) =>
                setConfig({
                  ...config,
                  anomaly_detection: {
                    ...(config.anomaly_detection || {
                      prometheus_url: "http://localhost:9090",
                      check_interval_seconds: 60,
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
            Monitor traffic patterns via Prometheus and detect anomalies in real-time.
          </Text>

          {config.anomaly_detection?.enabled && (
            <Stack gap="sm">
              <TextInput
                label="Prometheus URL"
                placeholder="http://prometheus:9090"
                value={config.anomaly_detection.prometheus_url || ""}
                onChange={(e) => setConfig({...config, anomaly_detection: {...config.anomaly_detection!, prometheus_url: e.currentTarget.value}})}
                disabled={formDisabled}
              />
              <Group grow>
                <NumberInput
                  label="Check Interval (s)"
                  min={10}
                  value={config.anomaly_detection.check_interval_seconds}
                  onChange={(v) => setConfig({...config, anomaly_detection: {...config.anomaly_detection!, check_interval_seconds: Number(v)}})}
                  disabled={formDisabled}
                />
                <NumberInput
                  label="Sensitivity"
                  decimalScale={2}
                  step={0.1}
                  min={0}
                  max={1}
                  value={config.anomaly_detection.sensitivity}
                  onChange={(v) => setConfig({...config, anomaly_detection: {...config.anomaly_detection!, sensitivity: Number(v)}})}
                  disabled={formDisabled}
                />
              </Group>
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
              <Switch
                label="XDP Rate Limiting"
                description="Drop packets at the network driver level"
                checked={config.ebpf.xdp_rate_limit || false}
                onChange={(e) => setConfig({...config, ebpf: {...config.ebpf!, xdp_rate_limit: e.currentTarget.checked}})}
                disabled={formDisabled}
              />
              <Switch
                label="TC Filtering"
                description="Kernel-level traffic classification and filtering"
                checked={config.ebpf.tc_filtering || false}
                onChange={(e) => setConfig({...config, ebpf: {...config.ebpf!, tc_filtering: e.currentTarget.checked}})}
                disabled={formDisabled}
              />
            </Stack>
          )}
        </Stack>
      </Card>

      <AppearanceCard colorScheme={colorScheme} setColorScheme={setColorScheme} />
    </Stack>
  );
}
