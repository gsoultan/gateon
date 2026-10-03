// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Stack, NumberInput, Select, Group, Text } from "@mantine/core";

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
      <Group grow align="start">
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
          description={
            config.storage === "redis"
              ? "Shared by every instance. Needs Redis configured for this gateway (Settings > Redis); the save is refused without it."
              : "Counted in each instance's memory: N instances allow N times the limit."
          }
          data={[
            { label: "Local (Memory)", value: "local" },
            { label: "Redis (shared)", value: "redis" },
          ]}
          value={config.storage || "local"}
          onChange={(val) => updateConfig("storage", val || "local")}
        />
      </Group>
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
      <ClientAddressNote />
    </Stack>
  );
}

/**
 * Where the per-middleware "Trust Cloudflare Headers" switch was. It never
 * changed the address a middleware saw: the entrypoint resolves the client
 * once, under the global setting, for every middleware (ADR 0046).
 */
export function ClientAddressNote() {
  return (
    <Text size="xs" c="dimmed">
      The client IP is the one the entrypoint resolved for every middleware. Behind Cloudflare, turn on Trust
      Cloudflare Headers in Settings (or GATEON_TRUST_CLOUDFLARE_HEADERS); it cannot be set per middleware.
    </Text>
  );
}
