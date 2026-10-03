// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Stack, Select, NumberInput, Text } from "@mantine/core";

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
