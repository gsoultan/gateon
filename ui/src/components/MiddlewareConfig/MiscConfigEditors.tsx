// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Stack, TextInput, Group, NumberInput, Switch, TagsInput, Select } from "@mantine/core";
import { KeyValueList } from "./KeyValueList";

export const CORS_PRESETS: Record<string, Record<string, string>> = {
  permissive: {
    allowedOrigins: "*",
    allowedMethods: "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH",
    allowedHeaders: "*",
    exposedHeaders: "*",
    allowCredentials: "true",
    maxAge: "86400",
  },
  standard: {
    allowedOrigins: "*",
    allowedMethods: "GET, POST, OPTIONS",
    allowedHeaders: "Content-Type, Authorization, Accept",
    exposedHeaders: "Content-Length, Content-Type",
    allowCredentials: "true",
    maxAge: "3600",
  },
  "grpc-web": {
    allowedOrigins: "*",
    allowedMethods: "POST, OPTIONS",
    allowedHeaders: "Content-Type, X-User-Agent, X-Grpc-Web, Grpc-Timeout",
    exposedHeaders: "Grpc-Status, Grpc-Message, Grpc-Encoding, Grpc-Accept-Encoding, X-Grpc-Web, X-Accept-Content-Transfer-Encoding, X-Accept-Response-Streaming",
    allowCredentials: "true",
    maxAge: "86400",
  },
  restricted: {
    allowedOrigins: "",
    allowedMethods: "GET",
    allowedHeaders: "Accept",
    exposedHeaders: "",
    allowCredentials: "false",
    maxAge: "600",
  },
};

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
  const splitTags = (val: string) => (val || "").split(",").map((s) => s.trim()).filter(Boolean);
  const joinTags = (tags: string[]) => tags.join(", ");

  const applyPreset = (presetName: string) => {
    if (!presetName) {
      updateConfig("preset", "");
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
        ]}
        value={config.preset || ""}
        onChange={(val) => applyPreset(val || "")}
        clearable
        description="Choosing a preset will populate fields below with common defaults."
      />

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
  const joinTags = (tags: string[]) => tags.join(", ");

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
