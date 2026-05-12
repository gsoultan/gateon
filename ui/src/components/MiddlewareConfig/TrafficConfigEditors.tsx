import { Stack, Select, NumberInput } from "@mantine/core";

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
      <NumberInput
        label="Max Response Body (Bytes)"
        placeholder="1048576"
        value={parseInt(config.max_response_body_bytes) || 1048576}
        onChange={(val) =>
          updateConfig("max_response_body_bytes", (val ?? 1048576).toString())
        }
        min={0}
      />
    </Stack>
  );
}

export function InFlightReqConfigEditor({ config, updateConfig }: EditorProps) {
  return (
    <Stack gap="md">
      <NumberInput
        label="Max Concurrent Requests"
        placeholder="100"
        value={parseInt(config.amount) || 100}
        onChange={(val) => updateConfig("amount", (val ?? 100).toString())}
        min={1}
      />
    </Stack>
  );
}
