import { Stack, NumberInput, Select, Switch, Group } from "@mantine/core";

interface RatelimitConfigEditorProps {
  config: Record<string, string>;
  onChange: (config: Record<string, string>) => void;
}

export function RatelimitConfigEditor({ config, onChange }: RatelimitConfigEditorProps) {
  const updateConfig = (key: string, value: string) => {
    onChange({ ...config, [key]: value });
  };

  return (
    <Stack gap="md">
      <Group grow>
        <NumberInput
          label="Requests Per Minute"
          value={parseInt(config.requests_per_minute) || 0}
          onChange={(val) => updateConfig("requests_per_minute", val.toString())}
          min={1}
        />
        <NumberInput
          label="Burst"
          value={parseInt(config.burst) || 0}
          onChange={(val) => updateConfig("burst", val.toString())}
          min={0}
        />
        <Select
          label="Storage"
          data={[
            { label: "Local (Memory)", value: "local" },
            { label: "Redis", value: "redis" },
          ]}
          value={config.storage || "local"}
          onChange={(val) => updateConfig("storage", val || "local")}
        />
      </Group>
      <Group grow align="start">
        <Select
          label="Limit Strategy"
          description="How to identify clients for rate limiting."
          data={[
            { label: "Client IP", value: "ip" },
            { label: "Tenant ID (Requires Auth)", value: "tenant" },
            { label: "JA4H Fingerprint (Recommended)", value: "ja4h" },
            { label: "Detailed Fingerprint (Strict)", value: "fingerprint" },
          ]}
          value={config.strategy || (config.per_tenant === "true" ? "tenant" : "ip")}
          onChange={(val) => updateConfig("strategy", val || "ip")}
        />
        <Stack gap="xs">
          <Switch
            label="Trust Cloudflare Headers"
            description="Use CF-Connecting-IP when behind Cloudflare."
            checked={config.trust_cloudflare_headers === "true"}
            onChange={(e) =>
              updateConfig(
                "trust_cloudflare_headers",
                e.currentTarget.checked ? "true" : "false"
              )
            }
          />
        </Stack>
      </Group>
    </Stack>
  );
}
