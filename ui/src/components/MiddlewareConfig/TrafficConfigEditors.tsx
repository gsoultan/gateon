// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Stack, Select, NumberInput, Text, TextInput } from "@mantine/core";

interface EditorProps {
  config: Record<string, string>;
  updateConfig: (key: string, value: string) => void;
}

export function CacheConfigEditor({ config, updateConfig }: EditorProps) {
  return (
    <Stack gap="md">
      <Select
        label="Storage"
        data={[
          { label: "Memory (Local)", value: "memory" },
          { label: "Redis (Distributed)", value: "redis" },
        ]}
        value={config.storage || "memory"}
        onChange={(val) => updateConfig("storage", val || "memory")}
        description="Redis requires Redis enabled in Settings. Use for multi-instance deployments."
      />
      <NumberInput
        label="TTL (seconds)"
        value={parseInt(config.ttl_seconds) || 60}
        onChange={(val) => updateConfig("ttl_seconds", (val ?? 60).toString())}
        min={1}
        description="How long to cache GET responses"
      />
      <NumberInput
        label="Max Entries"
        value={parseInt(config.max_entries) || 1024}
        onChange={(val) => updateConfig("max_entries", (val ?? 1024).toString())}
        min={1}
        description="Memory only; Redis has no local limit"
      />
      <NumberInput
        label="Max Body (KB)"
        value={parseInt(config.max_body_kb) || 256}
        onChange={(val) => updateConfig("max_body_kb", (val ?? 256).toString())}
        min={1}
        description="Skip caching responses larger than this"
      />
    </Stack>
  );
}

export function BufferingConfigEditor({ config, updateConfig }: EditorProps) {
  return (
    <Stack gap="md">
      <NumberInput
        label="Max Request Body (Bytes)"
        placeholder="1048576"
        value={parseInt(config.max_request_body_bytes) || 1048576}
        onChange={(val) =>
          updateConfig("max_request_body_bytes", (val ?? 1048576).toString())
        }
        min={0}
      />
      <Text size="xs" c="dimmed">
        This middleware buffers requests only. To cap a response, use the WAF
        middleware's Response Body Limit.
      </Text>
    </Stack>
  );
}

// The circuit breaker could not be created from the dashboard at all (ADR
// 0047). Every field is optional: an empty one takes the gateway's default,
// shown as the placeholder, and the keys are the ones circuitBreakerFromConfig
// reads. Durations are Go durations ("10s", "1m").
export function CircuitBreakerConfigEditor({ config, updateConfig }: EditorProps) {
  return (
    <Stack gap="md">
      <Text size="sm" c="dimmed">
        Stops sending this route's requests to its backend once too many fail, answering 503
        instead, and lets one request through after the sleep window to see whether it has
        recovered.
      </Text>
      <NumberInput
        label="Error Threshold"
        description="Share of requests in a window that must fail (5xx) to open the circuit, from 0.01 to 1. Default 0.5."
        placeholder="0.5"
        value={config.error_threshold ? Number(config.error_threshold) : ""}
        onChange={(val) => updateConfig("error_threshold", val === "" ? "" : String(val))}
        min={0.01}
        max={1}
        step={0.05}
        decimalScale={2}
      />
      <NumberInput
        label="Minimum Requests"
        description="Requests a window must hold before its error share is judged. Default 20."
        placeholder="20"
        value={config.min_requests ? parseInt(config.min_requests) : ""}
        onChange={(val) => updateConfig("min_requests", val === "" ? "" : String(val))}
        min={1}
      />
      <TextInput
        label="Window"
        description="How long requests are counted before the count starts over. Default 10s."
        placeholder="10s"
        value={config.window_size || ""}
        onChange={(e) => updateConfig("window_size", e.currentTarget.value.trim())}
      />
      <TextInput
        label="Sleep Window"
        description="How long the circuit stays open before one request probes the backend. Default 30s."
        placeholder="30s"
        value={config.sleep_window || ""}
        onChange={(e) => updateConfig("sleep_window", e.currentTarget.value.trim())}
      />
    </Stack>
  );
}

// The cap is per client address unless per_ip is "false", when it is one total
// for the route the middleware is attached to (ADR 0047). The label says which.
export function InFlightReqConfigEditor({ config, updateConfig }: EditorProps) {
  const total = config.per_ip === "false";
  return (
    <Stack gap="md">
      <Select
        label="Count Concurrent Requests"
        data={[
          { label: "Per client address", value: "true" },
          { label: "In total, for each route this is attached to", value: "false" },
        ]}
        value={total ? "false" : "true"}
        onChange={(val) => updateConfig("per_ip", val === "false" ? "false" : "true")}
        allowDeselect={false}
        description={
          total
            ? "One count shared by every client. Requests over it get 503."
            : "Each client address has its own count. Requests over it get 429; other addresses are unaffected."
        }
      />
      <NumberInput
        label={total ? "Max Concurrent Requests (total)" : "Max Concurrent Requests per Client Address"}
        placeholder="100"
        value={config.amount ? parseInt(config.amount) : ""}
        onChange={(val) => updateConfig("amount", val === "" ? "" : String(val))}
        min={1}
        required
      />
    </Stack>
  );
}
