// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Stack, TextInput, Group, NumberInput, Switch, TagsInput, Select, Text } from "@mantine/core";
import { KeyValueList } from "./KeyValueList";

// Keyed the way the editor fields below and internal/middleware/cors_factory.go
// read the config map; applying a preset spreads these straight into it.
export const CORS_PRESETS: Record<string, Record<string, string>> = {
  permissive: {
    allowed_origins: "*",
    allowed_methods: "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH",
    allowed_headers: "*",
    exposed_headers: "*",
    allow_credentials: "true",
    max_age: "86400",
  },
  standard: {
    allowed_origins: "*",
    allowed_methods: "GET, POST, OPTIONS",
    allowed_headers: "Content-Type, Authorization, Accept",
    exposed_headers: "Content-Length, Content-Type",
    allow_credentials: "true",
    max_age: "3600",
  },
  "grpc-web": {
    allowed_origins: "*",
    allowed_methods: "POST, OPTIONS",
    allowed_headers: "Content-Type, X-User-Agent, X-Grpc-Web, Grpc-Timeout",
    exposed_headers: "Grpc-Status, Grpc-Message, Grpc-Encoding, Grpc-Accept-Encoding, X-Grpc-Web, X-Accept-Content-Transfer-Encoding, X-Accept-Response-Streaming",
    allow_credentials: "true",
    max_age: "86400",
  },
  restricted: {
    allowed_origins: "",
    allowed_methods: "GET",
    allowed_headers: "Accept",
    exposed_headers: "",
    allow_credentials: "false",
    max_age: "600",
  },
};

// Not a policy but the absence of one: the route's CORS is its backend's. The
// gateway answers no preflight and adds or strips no header, so there is
// nothing to fill in (internal/middleware/transform/cors_presets.go).
export const CORS_BACKEND_PRESET = "backend";

interface EditorProps {
  config: Record<string, string>;
  updateConfig: (key: string, value: string) => void;
  onChange: (config: Record<string, string>) => void;
}

export function RewriteConfigEditor({ config, updateConfig, onChange }: EditorProps) {
  return (
    <Stack gap="md">
      <TextInput
        label="Path"
        placeholder="/new-path"
        value={config.path || ""}
        onChange={(e) => updateConfig("path", e.currentTarget.value)}
      />
      <Group grow>
        <TextInput
          label="Regex Pattern"
          placeholder="/old/(.*)"
          value={config.pattern || ""}
          onChange={(e) => updateConfig("pattern", e.currentTarget.value)}
        />
        <TextInput
          label="Replacement"
          placeholder="/new/$1"
          value={config.replacement || ""}
          onChange={(e) => updateConfig("replacement", e.currentTarget.value)}
        />
      </Group>
      <KeyValueList
        config={config}
        onChange={onChange}
        title="Add Query Parameters"
        prefix="query_"
        placeholderKey="param"
        placeholderValue="value"
      />
    </Stack>
  );
}

export function CORSConfigEditor({ config, updateConfig, onChange }: EditorProps) {
  const applyPreset = (presetName: string) => {
    if (!presetName) {
      updateConfig("preset", "");
      return;
    }
    if (presetName === CORS_BACKEND_PRESET) {
      onChange({ preset: CORS_BACKEND_PRESET });
      return;
    }
    const preset = CORS_PRESETS[presetName];
    if (preset) {
      onChange({
        ...config,
        ...preset,
        preset: presetName,
      });
    }
  };

  return (
    <Stack gap="md">
      <Select
        label="CORS Preset"
        placeholder="Select a preset to auto-fill"
        data={[
          { value: "permissive", label: "Permissive (Allow All)" },
          { value: "standard", label: "Standard HTTP" },
          { value: "grpc-web", label: "gRPC-Web Standard" },
          { value: "restricted", label: "Restricted" },
          { value: CORS_BACKEND_PRESET, label: "Backend's own (pass through)" },
        ]}
        value={config.preset || ""}
        onChange={(val) => applyPreset(val || "")}
        clearable
        description="Choosing a preset will populate fields below with common defaults."
      />

      {config.preset === CORS_BACKEND_PRESET ? (
        <Text size="sm" c="dimmed">
          The backend answers CORS for this route. The gateway passes preflights through and neither adds nor
          removes CORS headers — use this when the backend enforces its own origin allowlist.
        </Text>
      ) : (
        <CORSPolicyFields config={config} updateConfig={updateConfig} />
      )}
    </Stack>
  );
}

function CORSPolicyFields({ config, updateConfig }: Omit<EditorProps, "onChange">) {
  const splitTags = (val: string) => (val || "").split(",").map((s) => s.trim()).filter(Boolean);
  const joinTags = (tags: string[]) => tags.join(", ");

  return (
    <Stack gap="md">

      <TagsInput
        label="Allowed Origins"
        placeholder="*, https://example.com"
        value={splitTags(config.allowed_origins)}
        onChange={(val) => updateConfig("allowed_origins", joinTags(val))}
        description="List of origins (e.g. *, https://example.com). Press Enter to add."
        styles={{ input: { minHeight: 60 } }}
        clearable
      />
      <TagsInput
        label="Allowed Methods"
        placeholder="GET, POST, PUT, DELETE, OPTIONS"
        data={["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]}
        value={splitTags(config.allowed_methods)}
        onChange={(val) => updateConfig("allowed_methods", joinTags(val))}
        description="List of HTTP methods. Select from dropdown or type and press Enter."
        styles={{ input: { minHeight: 60 } }}
        clearable
      />
      <TagsInput
        label="Allowed Headers"
        placeholder="Content-Type, Authorization, X-Request-ID"
        data={["Content-Type", "Authorization", "Accept", "Origin", "X-Requested-With", "X-Request-ID"]}
        value={splitTags(config.allowed_headers)}
        onChange={(val) => updateConfig("allowed_headers", joinTags(val))}
        description="List of headers. Select from dropdown or type and press Enter."
        styles={{ input: { minHeight: 60 } }}
        clearable
      />
      <TagsInput
        label="Exposed Headers"
        placeholder="X-Custom-Header, Content-Length"
        data={["Content-Length", "Content-Range", "X-Custom-Header"]}
        value={splitTags(config.exposed_headers)}
        onChange={(val) => updateConfig("exposed_headers", joinTags(val))}
        description="Headers that can be accessed from the client."
        styles={{ input: { minHeight: 60 } }}
        clearable
      />
      <Group grow>
        <NumberInput
          label="Max Age (seconds)"
          value={parseInt(config.max_age) || 86400}
          onChange={(val) => updateConfig("max_age", (val ?? 86400).toString())}
          min={0}
        />
        <Switch
          label="Allow Credentials"
          checked={config.allow_credentials === "true"}
          onChange={(e) =>
            updateConfig(
              "allow_credentials",
              e.currentTarget.checked ? "true" : "false"
            )
          }
          mt="xl"
        />
      </Group>
    </Stack>
  );
}

export function PrefixConfigEditor({ config, updateConfig }: Omit<EditorProps, 'onChange'>) {
  return (
    <TextInput
      label="Prefix"
      placeholder="/api"
      value={config.prefix || ""}
      onChange={(e) => updateConfig("prefix", e.currentTarget.value)}
    />
  );
}

export function StripPrefixConfigEditor({ config, updateConfig }: Omit<EditorProps, 'onChange'>) {
  const splitTags = (val: string) => (val || "").split(",").map((s) => s.trim()).filter(Boolean);
  // No space after the comma: the gateway splits "prefixes" on "," without
  // trimming, so " /v1" is a prefix no path ever starts with.
  const joinTags = (tags: string[]) => tags.join(",");

  return (
    <TagsInput
      label="Prefixes"
      placeholder="/api, /v1"
      value={splitTags(config.prefixes)}
      onChange={(val) => updateConfig("prefixes", joinTags(val))}
      description="List of prefixes to strip from the request path."
      clearable
    />
  );
}

export function StripPrefixRegexConfigEditor({ config, updateConfig }: Omit<EditorProps, 'onChange'>) {
  return (
    <TextInput
      label="Regex"
      placeholder="^/api/[^/]+/"
      value={config.regex || ""}
      onChange={(e) => updateConfig("regex", e.currentTarget.value)}
    />
  );
}

export function ReplacePathConfigEditor({ config, updateConfig }: Omit<EditorProps, 'onChange'>) {
  return (
    <TextInput
      label="Path"
      placeholder="/new-path"
      value={config.path || ""}
      onChange={(e) => updateConfig("path", e.currentTarget.value)}
    />
  );
}

export function ReplacePathRegexConfigEditor({ config, updateConfig }: Omit<EditorProps, 'onChange'>) {
  return (
    <Group grow>
      <TextInput
        label="Pattern"
        placeholder="^/api/(.*)"
        value={config.pattern || ""}
        onChange={(e) => updateConfig("pattern", e.currentTarget.value)}
      />
      <TextInput
        label="Replacement"
        placeholder="/$1"
        value={config.replacement || ""}
        onChange={(e) => updateConfig("replacement", e.currentTarget.value)}
      />
    </Group>
  );
}
