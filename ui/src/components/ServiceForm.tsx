import { useEffect } from "react";
import {
  TextInput,
  Stack,
  Group,
  Button,
  Paper,
  Text,
  ActionIcon,
  Select,
  NumberInput,
  Alert,
  Tooltip,
  Switch,
  Autocomplete,
  Loader,
} from "@mantine/core";
import { IconPlus, IconTrash, IconCheck, IconInfoCircle, IconRefresh } from "@tabler/icons-react";
import { HealthCheckType, ProxyProtocolVersion, type Service } from "../types/gateon";
import { apiFetch, getApiErrorMessage } from "../hooks/useGateon";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "@tanstack/react-form";
import { notifications } from "@mantine/notifications";

export function ServiceForm({
  onSuccess,
  initialData,
}: {
  onSuccess?: () => void;
  initialData?: Service | null;
}) {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: async (newService: Service) => {
      const res = await apiFetch("/v1/services", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newService),
      });
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    },
    onSuccess: (savedService: Service) => {
      queryClient.invalidateQueries({ queryKey: ["services"] });
      notifications.show({
        title: "Service Saved",
        message: `Service ${savedService.id} has been successfully created/updated.`,
        color: "green",
        icon: <IconCheck size={18} />,
      });
      onSuccess?.();
    },
    onError: (err: unknown) => {
      notifications.show({
        title: "Error Saving Service",
        message: getApiErrorMessage(err),
        color: "red",
      });
    },
  });

  const discoverMutation = useMutation({
    mutationFn: async (args: { url: string; tls_config?: any }) => {
      const res = await apiFetch("/v1/discover/grpc", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(args),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || "Failed to discover gRPC services");
      }
      return res.json() as Promise<{ services: string[] }>;
    },
    onError: (err: unknown) => {
      notifications.show({
        title: "Discovery Failed",
        message: getApiErrorMessage(err),
        color: "red",
      });
    },
  });

  const PROTOCOL_HTTP = [
    { value: "http", label: "HTTP" },
    { value: "https", label: "HTTPS" },
  ] as const;
  const PROTOCOL_GRPC = [
    { value: "h2c", label: "h2c (HTTP/2 cleartext)" },
    { value: "h2", label: "h2 (HTTP/2 + TLS)" },
  ] as const;

  const form = useForm<Service>({
    defaultValues: {
      id: "",
      name: "",
      backend_type: "http",
      weighted_targets: [{
        url: "",
        weight: 1,
        protocol: "http",
        proxy_protocol_enabled: false,
        proxy_protocol_version: ProxyProtocolVersion.PROXY_PROTOCOL_VERSION_UNSPECIFIED,
      }],
      load_balancer_policy: "round_robin",
      health_check_path: "",
      health_check_port: 0,
      health_check_protocol: "",
      health_check_type: HealthCheckType.HEALTH_CHECK_TYPE_UNSPECIFIED,
      l4_health_check_interval_ms: 10000,
      l4_health_check_timeout_ms: 3000,
      l4_udp_session_timeout_s: 60,
      l4_proxy_protocol: false,
      discovery_url: "",
      tls_client_config: {
        enabled: false,
        cert_file: "",
        key_file: "",
        ca_file: "",
        skip_verify: true,
        server_name: "",
      },
    },
    onSubmit: async ({ value }) => {
      const bt = value.backend_type || "http";
      const isGRPC = bt === "grpc";
      const targets = value.weighted_targets
        .filter((t) => t.url.trim() !== "")
        .map((t) => {
          if (bt === "tcp" || bt === "udp") {
            const u = t.url.trim().replace(/^(https?|h2c?|tcp|udp):\/\//, "");
            return { ...t, url: u, protocol: "" };
          }
          const hostPart = t.url.trim().replace(/^(https?|h2c?):\/\//, "");
          const scheme =
            isGRPC
              ? t.protocol === "h2"
                ? "h2"
                : "h2c"
              : t.protocol === "https"
                ? "https"
                : "http";
          const protocol =
            isGRPC
              ? t.protocol || "h2c"
              : t.protocol || (scheme === "https" ? "https" : "http");
          return {
            ...t,
            url: `${scheme}://${hostPart}`,
            protocol,
            proxy_protocol_enabled: t.proxy_protocol_enabled ?? false,
            proxy_protocol_version:
              t.proxy_protocol_version ?? ProxyProtocolVersion.PROXY_PROTOCOL_VERSION_UNSPECIFIED,
          };
        });
      if (targets.length === 0) {
        notifications.show({
          title: "Validation Error",
          message: "At least one target is required.",
          color: "red",
        });
        return;
      }
      mutation.mutate({ ...value, weighted_targets: targets });
    },
  });

  useEffect(() => {
    if (initialData) {
      form.setFieldValue("id", initialData.id);
      form.setFieldValue("name", initialData.name);
      form.setFieldValue("backend_type", initialData.backend_type || "http");
      form.setFieldValue(
        "weighted_targets",
        initialData.weighted_targets?.length > 0
          ? initialData.weighted_targets.map((t) => {
              const bt = initialData.backend_type || "http";
              if (bt === "tcp" || bt === "udp") {
                const u = (t.url || "").replace(/^(https?|h2c?|tcp|udp):\/\//, "");
                return {
                  ...t,
                  url: u,
                  protocol: undefined,
                  proxy_protocol_enabled: t.proxy_protocol_enabled ?? false,
                  proxy_protocol_version:
                    t.proxy_protocol_version ?? ProxyProtocolVersion.PROXY_PROTOCOL_VERSION_UNSPECIFIED,
                };
              }
              const inferred =
                bt === "grpc"
                  ? t.url.startsWith("h2://")
                    ? "h2"
                    : t.url.startsWith("h2c://")
                      ? "h2c"
                      : t.url.startsWith("https")
                        ? "h2"
                        : "h2c"
                  : t.url.startsWith("https")
                    ? "https"
                    : "http";
              const p = t.protocol || inferred;
              return {
                ...t,
                protocol: p,
                proxy_protocol_enabled: t.proxy_protocol_enabled ?? false,
                proxy_protocol_version:
                  t.proxy_protocol_version ?? ProxyProtocolVersion.PROXY_PROTOCOL_VERSION_UNSPECIFIED,
              };
            })
          : [{
              url: "",
              weight: 1,
              protocol: "http",
              proxy_protocol_enabled: false,
              proxy_protocol_version: ProxyProtocolVersion.PROXY_PROTOCOL_VERSION_UNSPECIFIED,
            }],
      );
      form.setFieldValue(
        "load_balancer_policy",
        initialData.load_balancer_policy || "round_robin",
      );
      form.setFieldValue("health_check_path", initialData.health_check_path || "");
      form.setFieldValue("health_check_port", initialData.health_check_port ?? 0);
      form.setFieldValue("health_check_protocol", initialData.health_check_protocol || "");
      form.setFieldValue("health_check_type", initialData.health_check_type ?? HealthCheckType.HEALTH_CHECK_TYPE_UNSPECIFIED);
      form.setFieldValue(
        "l4_health_check_interval_ms",
        initialData.l4_health_check_interval_ms ?? 10000,
      );
      form.setFieldValue(
        "l4_health_check_timeout_ms",
        initialData.l4_health_check_timeout_ms ?? 3000,
      );
      form.setFieldValue(
        "l4_udp_session_timeout_s",
        initialData.l4_udp_session_timeout_s ?? 60,
      );
      form.setFieldValue("l4_proxy_protocol", initialData.l4_proxy_protocol ?? false);
      form.setFieldValue("discovery_url", initialData.discovery_url || "");
      form.setFieldValue("tls_client_config", initialData.tls_client_config || {
        enabled: false,
        cert_file: "",
        key_file: "",
        ca_file: "",
        skip_verify: true,
        server_name: "",
      });
    }
  }, [initialData, form]);

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        e.stopPropagation();
        form.handleSubmit();
      }}
    >
      <Stack gap="md">
        <form.Subscribe
          selector={(s) => s.values.backend_type}
          children={(backendType) => (
            <Alert
              icon={<IconInfoCircle size={18} />}
              color="indigo"
              variant="light"
              radius="md"
              title={
                backendType === "tcp" || backendType === "udp"
                  ? "L4 TCP/UDP backends"
                  : "HTTP & gRPC backends"
              }
            >
              <Text size="sm" c="dimmed">
                {backendType === "tcp" || backendType === "udp" ? (
                  <>
                    Targets use <code>host:port</code> (e.g. db1:5432, dns:53). Connect to L4 entrypoints via a Route
                    with type &quot;tcp&quot; or &quot;udp&quot;.
                  </>
                ) : (
                  <>
                    Targets can be HTTP or gRPC backends: <code>http://host:port</code> or{" "}
                    <code>https://host:port</code>.
                  </>
                )}
              </Text>
            </Alert>
          )}
        />

        <form.Field
          name="name"
          children={(field) => (
            <TextInput
              label="Service Name"
              description="A human-readable name for this backend service"
              required
              value={field.state.value}
              onBlur={field.handleBlur}
              onChange={(e) => field.handleChange(e.target.value)}
              placeholder="e.g. Auth Service, Payment API"
              size="md"
              radius="md"
            />
          )}
        />

        <form.Field
          name="backend_type"
          children={(field) => (
            <Select
              label="Backend Type"
              description="Determines target format and load balancing options"
              data={[
                { value: "http", label: "HTTP" },
                { value: "grpc", label: "gRPC" },
                { value: "graphql", label: "GraphQL" },
                { value: "tcp", label: "TCP (L4)" },
                { value: "udp", label: "UDP (L4)" },
              ]}
              value={field.state.value}
              onBlur={field.handleBlur}
              onChange={(v) => {
                const bt = (v || "http") as "http" | "grpc" | "graphql" | "tcp" | "udp";
                field.handleChange(bt);
                const targets = form.state.values.weighted_targets || [];
                const updated = targets.map((t: { url: string; weight: number; protocol?: string }) => {
                  if (bt === "tcp" || bt === "udp") {
                    const u = (t.url || "").replace(/^(https?|h2c?|tcp|udp):\/\//, "").trim();
                    return { ...t, url: u || "", protocol: undefined };
                  }
                  const scheme = t.protocol === "https" || t.protocol === "h2" ? "https" : "http";
                  const p = bt === "grpc" ? (scheme === "https" ? "h2" : "h2c") : scheme;
                  return { ...t, protocol: p };
                });
                form.setFieldValue("weighted_targets", updated);
              }}
            />
          )}
        />

        <form.Field
          name="discovery_url"
          children={(field) => (
            <TextInput
              label="Service Discovery URL"
              description="e.g. dns:my-service.local, consul:auth-svc, etcd:/services/api"
              value={field.state.value}
              onChange={(e) => field.handleChange(e.target.value)}
              placeholder="dns:..."
              size="md"
              radius="md"
            />
          )}
        />

        <Paper withBorder p="md" radius="md">
          <Stack gap="md">
            <Group justify="space-between" align="center">
              <div>
                <Group gap="xs">
                  <Text fw={600} size="sm">
                    Backend TLS (mTLS)
                  </Text>
                  <Tooltip label="Configure client certificates for authenticating to backend targets">
                    <IconInfoCircle size={14} color="gray" />
                  </Tooltip>
                </Group>
                <Text size="xs" c="dimmed" mt={2}>
                  Secure communication with backend services using client certificates.
                </Text>
              </div>
              <form.Field
                name="tls_client_config.enabled"
                children={(field) => (
                  <Switch
                    checked={field.state.value}
                    onChange={(e) => field.handleChange(e.currentTarget.checked)}
                    size="sm"
                  />
                )}
              />
            </Group>

            <form.Subscribe
              selector={(s) => s.values.tls_client_config?.enabled}
              children={(enabled) =>
                enabled && (
                  <Stack gap="sm">
                    <form.Field
                      name="tls_client_config.cert_file"
                      children={(field) => (
                        <TextInput
                          label="Client Certificate Path"
                          placeholder="/path/to/client.crt"
                          value={field.state.value}
                          onChange={(e) => field.handleChange(e.target.value)}
                          size="xs"
                        />
                      )}
                    />
                    <form.Field
                      name="tls_client_config.key_file"
                      children={(field) => (
                        <TextInput
                          label="Client Private Key Path"
                          placeholder="/path/to/client.key"
                          value={field.state.value}
                          onChange={(e) => field.handleChange(e.target.value)}
                          size="xs"
                        />
                      )}
                    />
                    <form.Field
                      name="tls_client_config.ca_file"
                      children={(field) => (
                        <TextInput
                          label="CA Certificate Path"
                          placeholder="/path/to/ca.crt"
                          value={field.state.value}
                          onChange={(e) => field.handleChange(e.target.value)}
                          size="xs"
                        />
                      )}
                    />
                    <Group grow>
                      <form.Field
                        name="tls_client_config.server_name"
                        children={(field) => (
                          <TextInput
                            label="Server Name (SNI Override)"
                            placeholder="backend.example.com"
                            value={field.state.value}
                            onChange={(e) => field.handleChange(e.target.value)}
                            size="xs"
                          />
                        )}
                      />
                      <form.Field
                        name="tls_client_config.skip_verify"
                        children={(field) => (
                          <Switch
                            label="Insecure Skip Verify"
                            checked={field.state.value}
                            onChange={(e) => field.handleChange(e.currentTarget.checked)}
                            mt="xl"
                          />
                        )}
                      />
                    </Group>
                  </Stack>
                )
              }
            />
          </Stack>
        </Paper>

        <Paper withBorder p="md" radius="md">
          <Stack gap="md">
            <Group justify="space-between" align="center">
              <div>
                <Text fw={600} size="sm">
                  Backend Targets
                </Text>
                <Text size="xs" c="dimmed" mt={2}>
                  Add one or more backend URLs. Load is distributed by the selected policy.
                </Text>
              </div>
              <Button
                variant="light"
                size="xs"
                leftSection={<IconPlus size={14} />}
                onClick={() => {
                  const bt = form.state.values.backend_type || "http";
                  form.pushFieldValue("weighted_targets", {
                    url: "",
                    weight: 1,
                    protocol: bt === "tcp" || bt === "udp" ? undefined : bt === "grpc" ? "h2c" : "http",
                    proxy_protocol_enabled: false,
                    proxy_protocol_version: ProxyProtocolVersion.PROXY_PROTOCOL_VERSION_UNSPECIFIED,
                  });
                }}
              >
                Add Target
              </Button>
            </Group>

            <form.Field
              name="weighted_targets"
              mode="array"
              children={(field) => (
                <Stack gap="sm">
                  {field.state.value.map((_, i) => {
                    const backendType = form.state.values.backend_type || "http";
                    const isL4 = backendType === "tcp" || backendType === "udp";
                    const protocolOpts = backendType === "grpc" ? PROTOCOL_GRPC : PROTOCOL_HTTP;
                    const currentProtocol = field.state.value[i]?.protocol;
                    const protocol = currentProtocol && protocolOpts.some((o) => o.value === currentProtocol)
                      ? currentProtocol
                      : backendType === "grpc"
                        ? "h2c"
                        : "http";
                    return (
                    <Paper key={i} withBorder p="sm" radius="md" style={{ backgroundColor: "var(--mantine-color-default-hover)" }}>
                      <Group gap="sm" align="flex-end" wrap="nowrap">
                        {!isL4 && (
                          <form.Field
                            name={`weighted_targets[${i}].protocol`}
                            children={(protoField) => (
                              <Select
                                label={i === 0 ? "Protocol" : undefined}
                                data={protocolOpts}
                                value={protoField.state.value || protocol}
                                onChange={(v) => {
                                  protoField.handleChange(v || protocol);
                                  const url = field.state.value[i]?.url ?? "";
                                  if (url) {
                                    const host = url.replace(/^(https?|h2c?):\/\//, "") || url;
                                    const scheme =
                                      backendType === "grpc"
                                        ? v === "h2"
                                          ? "h2"
                                          : "h2c"
                                        : v === "https"
                                          ? "https"
                                          : "http";
                                    form.setFieldValue(`weighted_targets[${i}].url`, `${scheme}://${host}`);
                                  }
                                }}
                                style={{ minWidth: 140 }}
                                size="sm"
                              />
                            )}
                          />
                        )}
                        <form.Field
                          name={`weighted_targets[${i}].url`}
                          children={(urlField) => (
                            <TextInput
                              label={i === 0 ? (isL4 ? "Address (host:port)" : "URL (host:port)") : undefined}
                              placeholder={isL4 ? "db1:5432 or dns:53" : "localhost:8080 or backend.example.com:443"}
                              value={(urlField.state.value || "").replace(/^(https?|h2c?|tcp|udp):\/\//, "")}
                              onBlur={urlField.handleBlur}
                              onChange={(e) => {
                                const v = e.target.value;
                                if (isL4) {
                                  urlField.handleChange(v.trim());
                                } else {
                                  const p = field.state.value[i]?.protocol;
                                  const scheme =
                                    backendType === "grpc"
                                      ? p === "h2"
                                        ? "h2"
                                        : "h2c"
                                      : p === "https" || p === "h2"
                                        ? "https"
                                        : "http";
                                  const withScheme =
                                    v.startsWith("http") || v.startsWith("h2")
                                      ? v
                                      : `${scheme}://${v}`;
                                  urlField.handleChange(v ? withScheme : "");
                                }
                              }}
                              style={{ flex: 1, minWidth: 180 }}
                              size="sm"
                            />
                          )}
                        />
                        {!isL4 && (
                          <form.Field
                            name={`weighted_targets[${i}].weight`}
                            children={(weightField) => (
                              <Tooltip label="Higher weight = more traffic.">
                                <NumberInput
                                  label={i === 0 ? "Weight" : undefined}
                                  value={weightField.state.value}
                                  onBlur={weightField.handleBlur}
                                  onChange={(v) => weightField.handleChange(Number(v))}
                                  style={{ maxWidth: 90 }}
                                  min={1}
                                  size="sm"
                                />
                              </Tooltip>
                            )}
                          />
                        )}
                        <ActionIcon
                          color="red"
                          variant="subtle"
                          size="lg"
                          onClick={() => form.removeFieldValue("weighted_targets", i)}
                          disabled={field.state.value.length === 1}
                          style={{ marginBottom: 2 }}
                        >
                          <IconTrash size={16} />
                        </ActionIcon>
                      </Group>
                    </Paper>
                  )})}
                </Stack>
              )}
            />
          </Stack>
        </Paper>

        <form.Field
          name="load_balancer_policy"
          children={(field) => {
            const bt = form.state.values.backend_type || "http";
            const isL4 = bt === "tcp" || bt === "udp";
            const options = isL4
              ? [
                  { label: "Round Robin", value: "round_robin" },
                  { label: "Least Connections (TCP)", value: "least_conn" },
                ]
              : [
                  { label: "Round Robin", value: "round_robin" },
                  { label: "Least Connections", value: "least_conn" },
                  { label: "Weighted Round Robin", value: "weighted_round_robin" },
                ];
            return (
              <Tooltip
                label={
                  isL4
                    ? "Round Robin: rotate targets. Least Connections: prefer least busy (TCP only)."
                    : "Round Robin: rotate. Least Connections: prefer least busy. Weighted: use target weight."
                }
              >
                <div>
                  <Select
                    label="Load Balancer Policy"
                    description="How traffic is distributed across targets"
                    data={options}
                    value={field.state.value}
                    onBlur={field.handleBlur}
                    onChange={(v) => field.handleChange(v || "round_robin")}
                  />
                </div>
              </Tooltip>
            );
          }}
        />

        <form.Subscribe
          selector={(s) => s.values.backend_type}
          children={(backendType) =>
            (backendType === "tcp" || backendType === "udp") ? (
              <>
                {backendType === "tcp" && (
                  <form.Field
                    name="l4_proxy_protocol"
                    children={(field) => (
                      <Tooltip label="Send HAProxy PROXY protocol v1 header so the backend (e.g. mail server) sees the original client IP. Required for correct SPF checks when proxying SMTP/IMAP/POP3.">
                        <div>
                          <Switch
                            label="Send PROXY protocol (TCP)"
                            description="Enable for email backends (SPF uses client IP)"
                            checked={field.state.value ?? false}
                            onBlur={field.handleBlur}
                            onChange={(e) => field.handleChange(e.currentTarget.checked)}
                          />
                        </div>
                      </Tooltip>
                    )}
                  />
                )}
                <Group grow>
                <form.Field
                  name="l4_health_check_interval_ms"
                  children={(field) => (
                    <TextInput
                      label="TCP Health Check Interval (ms)"
                      description="0 = disabled"
                      type="number"
                      placeholder="10000"
                      value={field.state.value ?? 10000}
                      onChange={(e) => field.handleChange(Number(e.target.value) || 0)}
                      size="md"
                    />
                  )}
                />
                <form.Field
                  name="l4_health_check_timeout_ms"
                  children={(field) => (
                    <TextInput
                      label="Health Check Timeout (ms)"
                      type="number"
                      placeholder="3000"
                      value={field.state.value ?? 3000}
                      onChange={(e) => field.handleChange(Number(e.target.value) || 3000)}
                      size="md"
                    />
                  )}
                />
                <form.Field
                  name="l4_udp_session_timeout_s"
                  children={(field) => (
                    <TextInput
                      label="UDP Session Timeout (s)"
                      description="UDP only"
                      type="number"
                      placeholder="60"
                      value={field.state.value ?? 60}
                      onChange={(e) => field.handleChange(Number(e.target.value) || 60)}
                      size="md"
                    />
                  )}
                />
              </Group>
              </>
            ) : null
          }
        />

        <form.Subscribe
          selector={(s) => [s.values.backend_type, s.values.health_check_type] as const}
          children={([backendType, healthCheckType]) =>
            backendType !== "tcp" && backendType !== "udp" ? (
              <>
                <form.Field
                  name="health_check_type"
                  children={(field) => (
                    <Select
                      label="Health Check Type"
                      description="Choose standard HTTP or gRPC health checking"
                      data={[
                        { value: HealthCheckType.HEALTH_CHECK_TYPE_UNSPECIFIED.toString(), label: "Auto (Detect from protocol)" },
                        { value: HealthCheckType.HEALTH_CHECK_TYPE_HTTP.toString(), label: "HTTP" },
                        { value: HealthCheckType.HEALTH_CHECK_TYPE_GRPC.toString(), label: "gRPC" },
                        { value: HealthCheckType.HEALTH_CHECK_TYPE_TCP.toString(), label: "TCP" },
                        { value: HealthCheckType.HEALTH_CHECK_TYPE_CUSTOM.toString(), label: "Custom" },
                      ]}
                      value={field.state.value?.toString()}
                      onBlur={field.handleBlur}
                      onChange={(v) => field.handleChange(Number(v) as HealthCheckType)}
                      size="md"
                    />
                  )}
                />
                <form.Field
                  name="health_check_path"
                  children={(field) => {
                    // Determine actual type if unspecified
                    let effectiveType = healthCheckType;
                    if (effectiveType === HealthCheckType.HEALTH_CHECK_TYPE_UNSPECIFIED) {
                      const bt = form.state.values.backend_type || "http";
                      effectiveType = bt === "grpc" ? HealthCheckType.HEALTH_CHECK_TYPE_GRPC : HealthCheckType.HEALTH_CHECK_TYPE_HTTP;
                    }

                    const isGRPC = effectiveType === HealthCheckType.HEALTH_CHECK_TYPE_GRPC;
                    const targets = form.state.values.weighted_targets;
                    const firstTarget = targets && targets.length > 0 ? targets[0] : null;

                    const handleDiscover = () => {
                      if (!firstTarget || !firstTarget.url) {
                        notifications.show({
                          title: "No Target URL",
                          message: "Please enter a target URL first",
                          color: "yellow",
                        });
                        return;
                      }

                      // Construct the full URL with scheme
                      let url = firstTarget.url;
                      if (!url.includes("://")) {
                        const scheme = firstTarget.protocol || (backendType === "grpc" ? "h2c" : "http");
                        url = `${scheme}://${url}`;
                      }

                      discoverMutation.mutate({
                        url,
                        tls_config: form.state.values.tls_client_config,
                      });
                    };

                    return (
                      <Tooltip label={isGRPC ? "Optional gRPC service name. Leave empty for the server's default health check." : "HTTP only. Leave empty to disable health checks for this service."}>
                        <div>
                          {isGRPC ? (
                            <Autocomplete
                              label="gRPC Service Name"
                              description="Optional service name to check"
                              placeholder="e.g. gateon.v1.ApiService or leave empty"
                              data={discoverMutation.data?.services || []}
                              value={field.state.value}
                              onBlur={field.handleBlur}
                              onChange={(val) => field.handleChange(val)}
                              rightSection={
                                discoverMutation.isPending ? (
                                  <Loader size="xs" />
                                ) : (
                                  <Tooltip label="Discover services from target (requires gRPC reflection)">
                                    <ActionIcon variant="subtle" onClick={handleDiscover} disabled={!firstTarget?.url}>
                                      <IconRefresh size={16} />
                                    </ActionIcon>
                                  </Tooltip>
                                )
                              }
                            />
                          ) : (
                            <TextInput
                              label="Health Check Path"
                              description="Optional HTTP path for health probes (e.g. /healthz)"
                              placeholder="/healthz or leave empty"
                              value={field.state.value}
                              onBlur={field.handleBlur}
                              onChange={(e) => field.handleChange(e.target.value)}
                            />
                          )}
                        </div>
                      </Tooltip>
                    );
                  }}
                />
                <Group grow>
                  <form.Field
                    name="health_check_port"
                    children={(field) => (
                      <TextInput
                        label="Health Check Port"
                        description="Override port (0 = use target port)"
                        type="number"
                        placeholder="0"
                        value={field.state.value ?? 0}
                        onBlur={field.handleBlur}
                        onChange={(e) => field.handleChange(Number(e.target.value) || 0)}
                        size="md"
                      />
                    )}
                  />
                  <form.Field
                    name="health_check_protocol"
                    children={(field) => (
                      <Select
                        label="Health Check Protocol"
                        description="Override scheme (empty = use target scheme)"
                        disabled={healthCheckType === HealthCheckType.HEALTH_CHECK_TYPE_GRPC}
                        data={[
                          { value: "", label: "Default (target scheme)" },
                          { value: "http", label: "HTTP" },
                          { value: "https", label: "HTTPS" },
                        ]}
                        value={field.state.value ?? ""}
                        onBlur={field.handleBlur}
                        onChange={(v) => field.handleChange(v ?? "")}
                        size="md"
                      />
                    )}
                  />
                </Group>
              </>
            ) : null
          }
        />

        <Button
          type="submit"
          loading={mutation.isPending}
          fullWidth
          mt="md"
          radius="md"
          size="md"
        >
          Save Service
        </Button>
      </Stack>
    </form>
  );
}
