import {
  Stack,
  TextInput,
  MultiSelect,
  NumberInput,
  Select,
  Text,
  Alert,
} from "@mantine/core";
import { IconInfoCircle } from "@tabler/icons-react";
import type { Route } from "../../types/gateon";
import type { useForm } from "@tanstack/react-form";
import { RuleBuilder } from "./RuleBuilder";

export type RouteFormApi = ReturnType<typeof useForm<Route>>;

interface RoutingConfigProps {
  form: RouteFormApi;
  entryPointOptions: { value: string; label: string }[];
}

export function RoutingConfig({ form, entryPointOptions }: RoutingConfigProps) {

  return (
    <Stack gap="md" mt="xl">
      <form.Field
        name="type"
        children={(field) => (
          <Select
            label="Route Type"
            description={
              field.state.value === "grpc"
                ? "gRPC: Use for gRPC backends. Requires a matching rule. Add the grpcweb middleware if called from browsers."
                : field.state.value === "graphql"
                  ? "GraphQL: Use for GraphQL API backends (HTTP). Requires a matching rule."
                  : field.state.value === "tcp"
                    ? "TCP: L4 proxy. No rule needed — matches by entrypoint."
                    : field.state.value === "udp"
                      ? "UDP: L4 proxy. No rule needed — matches by entrypoint."
                      : "HTTP: Use for REST/HTTP backends. Requires a matching rule."
            }
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
              const t = (v || "http") as "http" | "grpc" | "graphql" | "tcp" | "udp";
              field.handleChange(t);
              if (t === "tcp" || t === "udp") {
                form.setFieldValue("rule", "L4()");
              }
            }}
            required
          />
        )}
      />

      <form.Field
        name="name"
        children={(field) => (
          <TextInput
            label="Friendly Name"
            placeholder="My Application Route"
            required
            value={field.state.value || ""}
            onBlur={field.handleBlur}
            onChange={(e) => field.handleChange(e.target.value)}
            size="md"
            radius="md"
          />
        )}
      />

      <form.Field
        name="entrypoints"
        children={(field) => (
          <MultiSelect
            label="EntryPoints"
            description="Restrict this route to specific addresses (optional)"
            data={entryPointOptions}
            value={field.state.value}
            onBlur={field.handleBlur}
            onChange={(v) => field.handleChange(v)}
            placeholder="Select EntryPoints"
            searchable
            clearable
          />
        )}
      />

      <form.Field
        name="rule"
        children={(ruleField) => {
          const routeType = form.state.values.type;
          const isL4 = routeType === "tcp" || routeType === "udp";
          if (isL4) {
            return (
              <Alert
                icon={<IconInfoCircle size={18} />}
                color="blue"
                variant="light"
                title="TCP/UDP: No rule required"
              >
                L4 routes match traffic by the entrypoint and port. The rule <Text component="code" size="sm">L4()</Text> is set automatically. Just pick a TCP/UDP entrypoint and service.
              </Alert>
            );
          }
          return (
            <RuleBuilder
              value={ruleField.state.value}
              onChange={ruleField.handleChange}
              onBlur={ruleField.handleBlur}
              required
              error={ruleField.state.meta.errors?.[0]}
            />
          );
        }}
      />

      <form.Field
        name="priority"
        children={(field) => (
          <NumberInput
            label="Priority"
            description="Higher matches first (default 0)"
            value={field.state.value}
            onBlur={field.handleBlur}
            onChange={(v) => field.handleChange(Number(v))}
            w={120}
          />
        )}
      />
    </Stack>
  );
}
