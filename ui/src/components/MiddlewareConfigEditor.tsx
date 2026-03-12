import {
  Stack,
  TextInput,
  NumberInput,
  Switch,
  Select,
  Group,
  ActionIcon,
  Text,
  Divider,
  Button,
} from "@mantine/core";
import { IconPlus, IconTrash } from "@tabler/icons-react";

interface Props {
  type: string;
  config: Record<string, string>;
  onChange: (config: Record<string, string>) => void;
}

export function MiddlewareConfigEditor({ type, config, onChange }: Props) {
  const updateConfig = (key: string, value: string) => {
    onChange({ ...config, [key]: value });
  };

  const removeConfig = (key: string) => {
    const newConfig = { ...config };
    delete newConfig[key];
    onChange(newConfig);
  };

  // Common UI for key-value pairs (Headers, API Keys, Query Params)
  const KeyValueList = ({
    title,
    prefix,
    placeholderKey,
    placeholderValue,
    keyLabel = "Key",
    valueLabel = "Value",
  }: {
    title: string;
    prefix: string;
    placeholderKey: string;
    placeholderValue: string;
    keyLabel?: string;
    valueLabel?: string;
  }) => {
    const items = Object.entries(config)
      .filter(([k]) => k.startsWith(prefix))
      .map(([k, v]) => ({ fullKey: k, key: k.replace(prefix, ""), value: v }));

    return (
      <Stack gap="xs">
        <Text size="sm" fw={500}>
          {title}
        </Text>
        {items.map((item, index) => (
          <Group key={index} grow align="flex-start">
            <TextInput
              placeholder={placeholderKey}
              label={keyLabel}
              value={item.key}
              onChange={(e) => {
                const newKey = prefix + e.currentTarget.value;
                const newConfig = { ...config };
                delete newConfig[item.fullKey];
                newConfig[newKey] = item.value;
                onChange(newConfig);
              }}
            />
            <TextInput
              placeholder={placeholderValue}
              label={valueLabel}
              value={item.value}
              onChange={(e) =>
                updateConfig(item.fullKey, e.currentTarget.value)
              }
            />
            <ActionIcon
              color="red"
              variant="light"
              onClick={() => removeConfig(item.fullKey)}
              mt={24}
            >
              <IconTrash size={16} />
            </ActionIcon>
          </Group>
        ))}
        <Button
          variant="light"
          size="xs"
          leftSection={<IconPlus size={14} />}
          onClick={() => updateConfig(`${prefix}new_key_${Date.now()}`, "")}
          style={{ alignSelf: "flex-start" }}
        >
          Add {title}
        </Button>
      </Stack>
    );
  };

  switch (type) {
    case "ratelimit":
      return (
        <Stack gap="md">
          <Group grow>
            <NumberInput
              label="Requests Per Minute"
              value={parseInt(config.requests_per_minute) || 0}
              onChange={(val) =>
                updateConfig("requests_per_minute", val.toString())
              }
              min={1}
            />
            <NumberInput
              label="Burst"
              value={parseInt(config.burst) || 0}
              onChange={(val) => updateConfig("burst", val.toString())}
              min={0}
            />
          </Group>
          <Group grow>
            <Select
              label="Storage"
              data={[
                { label: "Local (Memory)", value: "local" },
                { label: "Redis", value: "redis" },
              ]}
              value={config.storage || "local"}
              onChange={(val) => updateConfig("storage", val || "local")}
            />
            <Switch
              label="Per IP Address"
              checked={config.per_ip === "true"}
              onChange={(e) =>
                updateConfig(
                  "per_ip",
                  e.currentTarget.checked ? "true" : "false",
                )
              }
              mt={25}
            />
          </Group>
        </Stack>
      );

    case "auth":
      return (
        <Stack gap="md">
          <Select
            label="Authentication Type"
            data={[
              { label: "JWT", value: "jwt" },
              { label: "API Key", value: "apikey" },
            ]}
            value={config.type || "jwt"}
            onChange={(val) => updateConfig("type", val || "jwt")}
          />
          {config.type === "apikey" ? (
            <KeyValueList
              title="API Keys"
              prefix="key_"
              placeholderKey="key-name"
              placeholderValue="actual-api-key"
              keyLabel="Tenant/Name"
              valueLabel="Key"
            />
          ) : (
            <>
              <TextInput
                label="Issuer"
                placeholder="https://auth.example.com"
                value={config.issuer || ""}
                onChange={(e) => updateConfig("issuer", e.currentTarget.value)}
              />
              <TextInput
                label="Audience"
                placeholder="my-api"
                value={config.audience || ""}
                onChange={(e) =>
                  updateConfig("audience", e.currentTarget.value)
                }
              />
              <TextInput
                label="Secret (Optional if using JWKS)"
                placeholder="HS256 Secret"
                value={config.secret || ""}
                onChange={(e) => updateConfig("secret", e.currentTarget.value)}
              />
            </>
          )}
        </Stack>
      );

    case "headers":
      return (
        <Stack gap="md">
          <KeyValueList
            title="Add Request Headers"
            prefix="add_request_"
            placeholderKey="X-Header"
            placeholderValue="Value"
          />
          <Divider />
          <KeyValueList
            title="Set Request Headers"
            prefix="set_request_"
            placeholderKey="X-Header"
            placeholderValue="Value"
          />
          <Divider />
          <KeyValueList
            title="Add Response Headers"
            prefix="add_response_"
            placeholderKey="X-Header"
            placeholderValue="Value"
          />
        </Stack>
      );

    case "rewrite":
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
              onChange={(e) =>
                updateConfig("replacement", e.currentTarget.value)
              }
            />
          </Group>
          <KeyValueList
            title="Add Query Parameters"
            prefix="query_"
            placeholderKey="param"
            placeholderValue="value"
          />
        </Stack>
      );

    case "addprefix":
      return (
        <TextInput
          label="Prefix"
          placeholder="/api"
          value={config.prefix || ""}
          onChange={(e) => updateConfig("prefix", e.currentTarget.value)}
        />
      );

    case "stripprefix":
      return (
        <TextInput
          label="Prefixes (comma separated)"
          placeholder="/api,/v1"
          value={config.prefixes || ""}
          onChange={(e) => updateConfig("prefixes", e.currentTarget.value)}
        />
      );

    case "stripprefixregex":
      return (
        <TextInput
          label="Regex"
          placeholder="^/api/[^/]+/"
          value={config.regex || ""}
          onChange={(e) => updateConfig("regex", e.currentTarget.value)}
        />
      );

    case "replacepath":
      return (
        <TextInput
          label="Path"
          placeholder="/new-path"
          value={config.path || ""}
          onChange={(e) => updateConfig("path", e.currentTarget.value)}
        />
      );

    case "replacepathregex":
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

    case "cors":
      return (
        <Stack gap="md">
          <TextInput
            label="Allowed Origins"
            placeholder="*, https://example.com"
            value={config.allowed_origins || ""}
            onChange={(e) =>
              updateConfig("allowed_origins", e.currentTarget.value)
            }
            description="Comma separated list of origins"
          />
          <TextInput
            label="Allowed Methods"
            placeholder="GET, POST, PUT, DELETE, OPTIONS"
            value={config.allowed_methods || ""}
            onChange={(e) =>
              updateConfig("allowed_methods", e.currentTarget.value)
            }
            description="Comma separated list of HTTP methods"
          />
          <TextInput
            label="Allowed Headers"
            placeholder="Content-Type, Authorization"
            value={config.allowed_headers || ""}
            onChange={(e) =>
              updateConfig("allowed_headers", e.currentTarget.value)
            }
            description="Comma separated list of headers"
          />
          <TextInput
            label="Exposed Headers"
            placeholder="X-Custom-Header"
            value={config.exposed_headers || ""}
            onChange={(e) =>
              updateConfig("exposed_headers", e.currentTarget.value)
            }
            description="Comma separated list of headers exposed to the client"
          />
          <Group grow>
            <NumberInput
              label="Max Age"
              value={parseInt(config.max_age) || 0}
              onChange={(val) => updateConfig("max_age", val.toString())}
              min={0}
              description="Seconds to cache preflight request"
            />
            <Switch
              label="Allow Credentials"
              checked={config.allow_credentials === "true"}
              onChange={(e) =>
                updateConfig(
                  "allow_credentials",
                  e.currentTarget.checked ? "true" : "false",
                )
              }
              mt={25}
            />
          </Group>
        </Stack>
      );

    case "retry":
      return (
        <NumberInput
          label="Attempts"
          value={parseInt(config.attempts) || 0}
          onChange={(val) => updateConfig("attempts", val.toString())}
          min={1}
        />
      );

    case "errors":
      return (
        <Stack gap="md">
          <TextInput
            label="Status Codes (comma separated)"
            placeholder="404, 500, 503"
            value={config.status_codes || ""}
            onChange={(e) =>
              updateConfig("status_codes", e.currentTarget.value)
            }
          />
          <KeyValueList
            title="Custom Error Pages"
            prefix="page_"
            placeholderKey="404"
            placeholderValue="/path/to/404.html"
            keyLabel="Status Code"
            valueLabel="Page Path"
          />
        </Stack>
      );

    case "accesslog":
    case "metrics":
      return (
        <TextInput
          label="Route ID Override (Optional)"
          placeholder="custom-id"
          value={config.route_id || ""}
          onChange={(e) => updateConfig("route_id", e.currentTarget.value)}
        />
      );

    case "compress":
      return (
        <Text size="sm" c="dimmed">
          No configuration needed for Gzip compression.
        </Text>
      );

    case "grpcweb":
      return (
        <Text size="sm" c="dimmed">
          No configuration needed. This middleware automatically converts
          gRPC-Web requests to standard gRPC.
        </Text>
      );

    default:
      return (
        <Text size="sm" c="red">
          Unknown middleware type: {type}
        </Text>
      );
  }
}
