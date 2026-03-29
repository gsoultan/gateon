import { Stack, TextInput, Group, NumberInput, Switch } from "@mantine/core";
import { KeyValueList } from "./KeyValueList";

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

export function CORSConfigEditor({ config, updateConfig }: Omit<EditorProps, 'onChange'>) {
  return (
    <Stack gap="md">
      <TextInput
        label="Allowed Origins"
        placeholder="*, https://example.com"
        value={config.allowed_origins || ""}
        onChange={(e) => updateConfig("allowed_origins", e.currentTarget.value)}
        description="Comma separated list of origins"
      />
      <TextInput
        label="Allowed Methods"
        placeholder="GET, POST, PUT, DELETE, OPTIONS"
        value={config.allowed_methods || ""}
        onChange={(e) => updateConfig("allowed_methods", e.currentTarget.value)}
        description="Comma separated list of HTTP methods"
      />
      <TextInput
        label="Allowed Headers"
        placeholder="Content-Type, Authorization, X-Request-ID"
        value={config.allowed_headers || ""}
        onChange={(e) => updateConfig("allowed_headers", e.currentTarget.value)}
        description="Comma separated list of headers"
      />
      <TextInput
        label="Exposed Headers"
        placeholder="X-Custom-Header, Content-Length"
        value={config.exposed_headers || ""}
        onChange={(e) => updateConfig("exposed_headers", e.currentTarget.value)}
        description="Headers that can be accessed from the client"
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
  return (
    <TextInput
      label="Prefixes (comma separated)"
      placeholder="/api,/v1"
      value={config.prefixes || ""}
      onChange={(e) => updateConfig("prefixes", e.currentTarget.value)}
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
