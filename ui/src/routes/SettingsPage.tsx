import { useState, useEffect } from "react";
import {
  Card,
  Title,
  Text,
  Stack,
  TextInput,
  NumberInput,
  Button,
  Group,
  Divider,
  Switch,
  useMantineColorScheme,
  Alert,
  SegmentedControl,
  Paper,
  Box,
  Center,
  Select,
  MultiSelect,
  ActionIcon,
  Tooltip,
  Code,
  CopyButton,
} from "@mantine/core";
import {
  IconSun,
  IconMoon,
  IconInfoCircle,
  IconDeviceDesktop,
  IconPalette,
  IconAdjustments,
  IconNetwork,
  IconShieldLock,
  IconBolt,
  IconCopy,
  IconCheck,
  IconRocket,
  IconDownload,
  IconUpload,
  IconUsers,
  IconKey,
  IconChartDots,
} from "@tabler/icons-react";
import { ConfigImportExportCard } from "../components/ConfigImportExportCard";
import { usePermissions } from "../hooks/usePermissions";
import { useAuthStore } from "../store/useAuthStore";
import { useApiConfigStore } from "../store/useApiConfigStore";
import type { GlobalConfig } from "../types/gateon";
import { Link } from "@tanstack/react-router";
import { apiFetch } from "../hooks/useGateon";

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

      <Card withBorder padding="xl" radius="lg" shadow="xs">
        <Stack gap="md">
          <Group gap="md">
            <Paper p="xs" radius="md" bg="teal.6">
              <IconRocket size={20} color="white" />
            </Paper>
            <div>
              <Title order={4} fw={700}>
                Quick Presets
              </Title>
              <Text c="dimmed" size="xs">
                One-click apply common configuration scenarios.
              </Text>
            </div>
          </Group>
          <Group gap="sm">
            <Button variant="light" color="gray" size="sm" radius="md" disabled={formDisabled} onClick={() => applyPreset("development")}>
              Development
            </Button>
            <Button variant="light" color="blue" size="sm" radius="md" disabled={formDisabled} onClick={() => applyPreset("production")}>
              Production
            </Button>
            <Button variant="light" color="teal" size="sm" radius="md" disabled={formDisabled} onClick={() => applyPreset("high-throughput")}>
              High-Throughput (100k+ req/s)
            </Button>
          </Group>
          <Text size="xs" c="dimmed">
            Presets update Gateway Configuration below. Remember to save after applying.
          </Text>
        </Stack>
      </Card>

      <ConfigImportExportCard canImport={canImportConfig} canExport={canExportConfig} />

      <Card withBorder padding="xl" radius="lg" shadow="xs">
        <Stack gap="lg">
          <Group gap="md">
            <Paper p="xs" radius="md" bg="blue.6">
              <IconAdjustments size={20} color="white" />
            </Paper>
            <div>
              <Title order={4} fw={700}>
                General Settings
              </Title>
              <Text c="dimmed" size="xs">
                Configure UI behavior and connection to the gateway.
              </Text>
            </div>
          </Group>

          <Divider />

          <Stack gap="md">
            <TextInput
              label="Gateway API URL"
              description="The base URL of the Gateon Management API"
              placeholder="http://localhost:8080"
              value={apiUrlDraft}
              onChange={(e) => setApiUrlDraft(e.currentTarget.value)}
              radius="md"
            />

            <NumberInput
              label="Metrics Refresh Interval (seconds)"
              description="How often to poll the gateway for real-time metrics"
              min={1}
              max={60}
              value={refreshIntervalDraft}
              onChange={(val) =>
                setRefreshIntervalDraft(typeof val === "number" ? val : 10)
              }
              radius="md"
            />
          </Stack>

          <Group justify="flex-end" mt="md" gap="sm">
            {generalSavedOk && (
              <Text size="sm" c="green" fw={500}>
                Saved
              </Text>
            )}
            <Button onClick={handleSave} radius="md" px="xl">
              Save Settings
            </Button>
          </Group>
        </Stack>
      </Card>

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
                      data={["TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"]}
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
                      data={["TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"]}
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
                label="Enable Redis (rate limiting and distributed cache)"
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
                  SECURITY (PASETO + SQLite)
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
                  <Group grow>
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
                    />
                    <TextInput
                      label="SQLite Database Path"
                      placeholder="gateon.db"
                      disabled={formDisabled}
                      value={config?.auth?.sqlite_path || ""}
                      onChange={(e) =>
                        setConfig({
                          ...config,
                          auth: {
                            ...(config?.auth || {}),
                            sqlite_path: e.currentTarget.value,
                          },
                        })
                      }
                      radius="md"
                    />
                  </Group>
                  <Alert
                    icon={<IconInfoCircle size={16} />}
                    color="blue"
                    variant="light"
                    radius="md"
                  >
                    Changing the secret key will invalidate all existing
                    sessions. The SQLite database stores users and roles for
                    RBAC.
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

      <Card withBorder padding="xl" radius="lg" shadow="xs">
        <Stack gap="lg">
          <Group gap="md">
            <Paper p="xs" radius="md" bg="violet.6">
              <IconPalette size={20} color="white" />
            </Paper>
            <div>
              <Title order={4} fw={700}>
                Appearance
              </Title>
              <Text c="dimmed" size="xs">
                Customize the look and feel of the dashboard.
              </Text>
            </div>
          </Group>

          <Divider />

          <Stack gap="xs">
            <Text size="sm" fw={700}>
              Theme Mode
            </Text>
            <SegmentedControl
              value={colorScheme}
              onChange={(value: "light" | "dark" | "auto") =>
                setColorScheme(value)
              }
              data={[
                {
                  value: "light",
                  label: (
                    <Center style={{ gap: 10 }}>
                      <IconSun size={16} />
                      <span>Light</span>
                    </Center>
                  ),
                },
                {
                  value: "dark",
                  label: (
                    <Center style={{ gap: 10 }}>
                      <IconMoon size={16} />
                      <span>Dark</span>
                    </Center>
                  ),
                },
                {
                  value: "auto",
                  label: (
                    <Center style={{ gap: 10 }}>
                      <IconDeviceDesktop size={16} />
                      <span>System</span>
                    </Center>
                  ),
                },
              ]}
              radius="md"
              size="md"
              fullWidth
            />
          </Stack>
        </Stack>
      </Card>
    </Stack>
  );
}
