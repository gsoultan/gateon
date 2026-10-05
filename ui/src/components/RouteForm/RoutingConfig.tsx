// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

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
import { ROUTE_STREAM_MODE, type Route } from "../../types/gateon";
import type { FormApi } from "@tanstack/react-form";
import { RuleBuilder } from "./RuleBuilder";

export type RouteFormApi = any;

interface RoutingConfigProps {
  form: RouteFormApi;
  entryPointOptions: { value: string; label: string }[];
}

export function RoutingConfig({ form, entryPointOptions }: RoutingConfigProps) {

  return (
    <Stack gap="md" mt="xl">
      <form.Field
        name="type"
        children={(field: any) => (
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
        children={(field: any) => (
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
        children={(field: any) => (
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
        children={(ruleField: any) => {
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
        name="streamMode"
        children={(field: any) => {
          const routeType = form.state.values.type;
          if (routeType === "tcp" || routeType === "udp") return null;
          return (
            <Select
              label="Streaming responses"
              description={STREAM_MODE_HELP[String(field.state.value ?? 0)]}
              data={STREAM_MODE_OPTIONS}
              value={String(field.state.value ?? ROUTE_STREAM_MODE.AUTO)}
              onBlur={field.handleBlur}
              onChange={(v) => field.handleChange(Number(v ?? ROUTE_STREAM_MODE.AUTO))}
              allowDeselect={false}
              w={{ base: "100%", sm: 360 }}
            />
          );
        }}
      />

      <form.Field
        name="priority"
        children={(field: any) => (
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

// Route.stream_mode (ADR 0064). Every mode keeps a stream bounded: a lifted
// response is ended by the stream idle timeout and maximum lifetime.
const STREAM_MODE_OPTIONS = [
  { value: String(ROUTE_STREAM_MODE.AUTO), label: "Automatic — event streams only (default)" },
  { value: String(ROUTE_STREAM_MODE.ALWAYS), label: "Always — every response streams" },
  { value: String(ROUTE_STREAM_MODE.NEVER), label: "Never — no response streams" },
];

const STREAM_MODE_HELP: Record<string, string> = {
  [ROUTE_STREAM_MODE.AUTO]:
    "A 200 text/event-stream response with no Content-Length outlives the entrypoint's read and write timeouts; every other response keeps them.",
  [ROUTE_STREAM_MODE.ALWAYS]:
    "For a backend that streams under another type (NDJSON, long-poll, chunked). Once the backend answers, every response outlives the entrypoint's timeouts, ended instead by the stream idle timeout and maximum lifetime. The backend must still answer within the write timeout.",
  [ROUTE_STREAM_MODE.NEVER]:
    "Every response, an event stream included, is cut at the entrypoint's write timeout.",
};
