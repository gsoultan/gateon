import { useEffect } from "react";
import {
  TextInput,
  Stack,
  Group,
  Button,
  Switch,
  Divider,
  Checkbox,
  Alert,
  Text,
} from "@mantine/core";
import {
  IconCheck,
  IconServer,
  IconShieldLock,
  IconClock,
  IconHash,
  IconLock,
  IconInfoCircle,
} from "@tabler/icons-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "@tanstack/react-form";
import { notifications } from "@mantine/notifications";
import { Protocol } from "../types/gateon";
import type { EntryPoint } from "../types/gateon";
import { apiFetch } from "../hooks/useGateon";

const DEFAULT_TIMEOUT_MS = 15000;

export function EntryPointForm({
  onSuccess,
  initialData,
}: {
  onSuccess?: () => void;
  initialData?: EntryPoint | null;
}) {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: async (newEP: EntryPoint) => {
      const res = await apiFetch("/v1/entrypoints", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newEP),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || `HTTP ${res.status}`);
      }
      return res.json();
    },
    onSuccess: (savedEP: EntryPoint) => {
      queryClient.invalidateQueries({ queryKey: ["entrypoints"] });
      notifications.show({
        title: "EntryPoint Saved",
        message: `EntryPoint ${savedEP.id} has been successfully created/updated.`,
        color: "green",
        icon: <IconCheck size={18} />,
      });
      onSuccess?.();
    },
    onError: (err: any) => {
      notifications.show({
        title: "Error Saving EntryPoint",
        message: err.message,
        color: "red",
      });
    },
  });

  // @ts-expect-error TanStack Form expects 12 type params; EntryPoint works at runtime
  const form = useForm<EntryPoint>({
    defaultValues: {
      id: "",
      name: "",
      address: "",
      type: 0, // Inferred by backend from address + protocols + TLS
      protocol: 0,
      protocols: [Protocol.TCP],
      tls: { enabled: false },
      read_timeout_ms: DEFAULT_TIMEOUT_MS,
      write_timeout_ms: DEFAULT_TIMEOUT_MS,
      max_connections: 0,
      access_log_enabled: true,
    },
    onSubmit: async ({ value }) => {
      try {
        await mutation.mutateAsync(value);
      } catch (e) {
        // Error is handled by mutation.onError
      }
    },
  });

  useEffect(() => {
    if (initialData) {
      form.setFieldValue("id", initialData.id);
      form.setFieldValue("type", initialData.type ?? 0);
      form.setFieldValue("name", initialData.name);
      form.setFieldValue("address", initialData.address);
      form.setFieldValue("protocol", initialData.protocol ?? Protocol.TCP);
      form.setFieldValue(
        "protocols",
        initialData.protocols && initialData.protocols.length > 0
          ? initialData.protocols
          : [initialData.protocol ?? Protocol.TCP],
      );
      form.setFieldValue("tls", initialData.tls || { enabled: false });
      form.setFieldValue(
        "read_timeout_ms",
        initialData.read_timeout_ms ?? DEFAULT_TIMEOUT_MS,
      );
      form.setFieldValue(
        "write_timeout_ms",
        initialData.write_timeout_ms ?? DEFAULT_TIMEOUT_MS,
      );
      form.setFieldValue("max_connections", initialData.max_connections || 0);
      form.setFieldValue(
        "access_log_enabled",
        initialData.access_log_enabled ?? true,
      );
    }
  }, [initialData, form]);

  const protocols = form.state.values.protocols ?? [Protocol.TCP];
  const tlsEnabled = form.state.values.tls?.enabled ?? false;
  const addr = form.state.values.address ?? "";
  const isHttpPort =
    addr.endsWith(":80") ||
    addr.endsWith(":443") ||
    addr.endsWith(":8080") ||
    addr.endsWith(":8443") ||
    addr.includes("http");
  const hasTCP = protocols.includes(Protocol.TCP);
  const hasUDP = protocols.includes(Protocol.UDP);
  // Inferred L4: TCP-only or UDP-only without TLS and not HTTP port
  const isL4TCP = hasTCP && !hasUDP && !tlsEnabled && !isHttpPort;
  const isL4UDP = hasUDP && !hasTCP && !tlsEnabled && !isHttpPort;
  const isL4 = isL4TCP || isL4UDP;

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        e.stopPropagation();
        form.handleSubmit();
      }}
    >
      <Stack gap="md">
        <form.Field
          name="name"
          children={(field) => (
            <TextInput
              label="EntryPoint Name"
              description="Friendly name for this entrypoint"
              placeholder="e.g. Public HTTP"
              leftSection={<IconHash size={16} />}
              value={field.state.value}
              onBlur={field.handleBlur}
              onChange={(e) => field.handleChange(e.target.value)}
              size="md"
              radius="md"
            />
          )}
        />

        <form.Field
          name="address"
          children={(field) => (
            <TextInput
              label="Listening Address"
              description="Interface and port to bind to"
              placeholder="e.g. :80 or 0.0.0.0:443"
              required
              leftSection={<IconServer size={16} />}
              value={field.state.value}
              onBlur={field.handleBlur}
              onChange={(e) => field.handleChange(e.target.value)}
              size="md"
              radius="md"
            />
          )}
        />

        {isL4 && (
          <Alert
            icon={<IconInfoCircle size={18} />}
            color="blue"
            variant="light"
            radius="md"
            title="L4 TCP/UDP proxy"
          >
            <Text size="sm" c="dimmed">
              Backends are configured via <strong>Routes</strong> and <strong>Services</strong>. Create a Route with
              type &quot;tcp&quot; or &quot;udp&quot;, select this entrypoint, and choose a Service with backend type
              tcp/udp and host:port targets.
            </Text>
          </Alert>
        )}

        <form.Field
          name="protocols"
          children={(field) => (
            <Checkbox.Group
              label="Network Protocols"
              description="Select one or both (TCP and UDP)"
              required
              value={(field.state.value ?? [Protocol.TCP]).map((v) => v.toString())}
              onChange={(vals) => field.handleChange(vals.map(Number))}
            >
              <Group mt="xs">
                <Checkbox
                  value={Protocol.TCP.toString()}
                  label="TCP (Recommended for HTTP/gRPC)"
                />
                <Checkbox
                  value={Protocol.UDP.toString()}
                  label="UDP (Required for HTTP/3)"
                />
              </Group>
            </Checkbox.Group>
          )}
        />

        <Divider
          label={
            <Group gap="xs">
              <IconShieldLock size={14} />
              <span>Security & Resilience</span>
            </Group>
          }
          labelPosition="center"
        />

        <form.Field
          name="tls.enabled"
          children={(field) => (
            <Switch
              label="Enable TLS"
              description={
                hasUDP && !hasTCP
                  ? "Enable for HTTP/3 (QUIC); leave off for raw UDP L4"
                  : "Enable secure encrypted communication"
              }
              checked={field.state.value}
              thumbIcon={
                field.state.value ? (
                  <IconLock size={12} color="var(--mantine-color-teal-6)" />
                ) : undefined
              }
              onChange={(e) => field.handleChange(e.currentTarget.checked)}
            />
          )}
        />

        <Group grow>
          <form.Field
            name="read_timeout_ms"
            children={(field) => (
              <TextInput
                label="Read Timeout"
                description="Max time to read request"
                placeholder="15000"
                type="number"
                leftSection={<IconClock size={16} />}
                rightSection={<span style={{ fontSize: 10, marginRight: 10 }}>ms</span>}
                value={field.state.value}
                onChange={(e) => field.handleChange(Number(e.target.value))}
                size="md"
                radius="md"
              />
            )}
          />
          <form.Field
            name="write_timeout_ms"
            children={(field) => (
              <TextInput
                label="Write Timeout"
                description="Max time to write response"
                placeholder="15000"
                type="number"
                leftSection={<IconClock size={16} />}
                rightSection={<span style={{ fontSize: 10, marginRight: 10 }}>ms</span>}
                value={field.state.value}
                onChange={(e) => field.handleChange(Number(e.target.value))}
                size="md"
                radius="md"
              />
            )}
          />
        </Group>

        <form.Field
          name="access_log_enabled"
          children={(field) => (
            <Switch
              label="Enable Access Logs"
              description="Record all incoming requests for this entrypoint"
              checked={field.state.value}
              onChange={(e) => field.handleChange(e.currentTarget.checked)}
            />
          )}
        />

        <Button
          type="submit"
          loading={mutation.isPending}
          leftSection={<IconCheck size={18} />}
          mt="md"
        >
          {initialData ? "Update EntryPoint" : "Create EntryPoint"}
        </Button>
      </Stack>
    </form>
  );
}
