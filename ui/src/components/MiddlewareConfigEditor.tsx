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

interface MiddlewareConfigEditorProps {
  type: string;
  config: Record<string, string>;
  onChange: (config: Record<string, string>) => void;
}

export function MiddlewareConfigEditor({ type, config, onChange }: MiddlewareConfigEditorProps) {
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

    case "inflightreq":
      return (
        <Stack gap="md">
          <NumberInput
            label="Max Concurrent Requests (amount)"
            description="Max in-flight requests per source. Returns 429 when exceeded."
            value={parseInt(config.amount) || 0}
            onChange={(val) => updateConfig("amount", val?.toString() || "0")}
            min={1}
          />
          <Switch
            label="Per IP Address"
            description="Limit per client IP. If false, limits per request host."
            checked={config.per_ip !== "false"}
            onChange={(e) =>
              updateConfig(
                "per_ip",
                e.currentTarget.checked ? "true" : "false"
              )
            }
          />
        </Stack>
      );

    case "buffering":
      return (
        <NumberInput
          label="Max Request Body (bytes)"
          description="Rejects requests exceeding this size with 413."
          value={parseInt(config.max_request_body_bytes) || 0}
          onChange={(val) =>
            updateConfig(
              "max_request_body_bytes",
              val?.toString() || "0"
            )
          }
          min={1}
        />
      );

    case "auth":
      return (
        <Stack gap="md">
          <Select
            label="Authentication Type"
            data={[
              { label: "JWT", value: "jwt" },
              { label: "API Key", value: "apikey" },
              { label: "Basic Auth", value: "basic" },
            ]}
            value={config.type || "jwt"}
            onChange={(val) => updateConfig("type", val || "jwt")}
          />
          {config.type === "apikey" && (
            <>
              <TextInput
                label="API Key Header"
                description="Header to read API key from. Default: X-API-Key"
                placeholder="X-API-Key"
                value={config.header || ""}
                onChange={(e) => updateConfig("header", e.currentTarget.value)}
              />
              <KeyValueList
                title="API Keys"
                prefix="key_"
                placeholderKey="tenant-name"
                placeholderValue="actual-api-key"
                keyLabel="Tenant/Name"
                valueLabel="Key"
              />
            </>
          )}
          {config.type === "basic" && (
            <>
              <TextInput
                label="Users"
                description="Single: use Username + Password below. Multiple: user1:pass1,user2:pass2"
                placeholder="admin:secret,user:pass"
                value={config.users || ""}
                onChange={(e) => updateConfig("users", e.currentTarget.value)}
              />
              <Group grow>
                <TextInput
                  label="Username (single user)"
                  placeholder="admin"
                  value={config.username || ""}
                  onChange={(e) =>
                    updateConfig("username", e.currentTarget.value)
                  }
                />
                <TextInput
                  label="Password (single user)"
                  type="password"
                  placeholder="••••••••"
                  value={config.password || ""}
                  onChange={(e) =>
                    updateConfig("password", e.currentTarget.value)
                  }
                />
              </Group>
              <TextInput
                label="Realm"
                description="Shown in browser auth prompt"
                placeholder="Gateon"
                value={config.realm || ""}
                onChange={(e) => updateConfig("realm", e.currentTarget.value)}
              />
            </>
          )}
          {config.type === "jwt" && (
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
          <Text size="sm" fw={600} c="dimmed" tt="uppercase">
            HSTS (Traefik-style)
          </Text>
          <Group grow>
            <NumberInput
              label="STS Seconds (max-age)"
              description="Set > 0 to add Strict-Transport-Security. 0 = disabled."
              value={parseInt(config.sts_seconds) || 0}
              onChange={(val) =>
                updateConfig("sts_seconds", (val ?? 0).toString())
              }
              min={0}
              placeholder="31536000"
            />
            <Switch
              label="Include Subdomains"
              description="stsIncludeSubdomains"
              checked={config.sts_include_subdomains === "true"}
              onChange={(e) =>
                updateConfig(
                  "sts_include_subdomains",
                  e.currentTarget.checked ? "true" : "false"
                )
              }
              mt={20}
            />
          </Group>
          <Group grow>
            <Switch
              label="Preload"
              description="Allow HSTS preload list submission"
              checked={config.sts_preload === "true"}
              onChange={(e) =>
                updateConfig(
                  "sts_preload",
                  e.currentTarget.checked ? "true" : "false"
                )
              }
            />
            <Switch
              label="Force STS (HTTP dev)"
              description="Add header over HTTP (for development)"
              checked={config.force_sts_header === "true"}
              onChange={(e) =>
                updateConfig(
                  "force_sts_header",
                  e.currentTarget.checked ? "true" : "false"
                )
              }
            />
          </Group>
          <Divider label="Custom Headers" labelPosition="center" />
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
          <KeyValueList
            title="Set Response Headers"
            prefix="set_response_"
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
        <Stack gap="md">
          <NumberInput
            label="Min Response Body (bytes)"
            description="Only compress responses larger than this. Default: 1024"
            value={parseInt(config.min_response_body_bytes) || 1024}
            onChange={(val) =>
              updateConfig(
                "min_response_body_bytes",
                (val ?? 1024).toString()
              )
            }
            min={0}
          />
          <TextInput
            label="Excluded Content-Types"
            description="Comma-separated; never compress these (e.g. image/png,image/jpeg)"
            placeholder="image/png, image/jpeg, image/gif"
            value={config.excluded_content_types || ""}
            onChange={(e) =>
              updateConfig("excluded_content_types", e.currentTarget.value)
            }
          />
          <TextInput
            label="Included Content-Types"
            description="If set, only compress these; leave empty to compress all except excluded"
            placeholder="text/html, application/json"
            value={config.included_content_types || ""}
            onChange={(e) =>
              updateConfig("included_content_types", e.currentTarget.value)
            }
          />
          <NumberInput
            label="Max Buffer (bytes)"
            description="Responses larger than this bypass compression (stream through). Default: 10MB"
            value={
              parseInt(config.max_buffer_bytes) || 10 * 1024 * 1024
            }
            onChange={(val) =>
              updateConfig(
                "max_buffer_bytes",
                (val ?? 10 * 1024 * 1024).toString()
              )
            }
            min={1024}
          />
        </Stack>
      );

    case "forwardauth":
      return (
        <Stack gap="md">
          <TextInput
            label="Address"
            description="Auth service URL (required). e.g. https://auth.example.com/verify"
            placeholder="https://auth.example.com/verify"
            value={config.address || ""}
            onChange={(e) =>
              updateConfig("address", e.currentTarget.value)
            }
            required
          />
          <TextInput
            label="Auth Response Headers"
            description="Comma-separated headers from auth 2xx to copy to the forwarded request (e.g. X-Forwarded-User)"
            placeholder="X-Forwarded-User, X-Auth-Request-Email"
            value={config.auth_response_headers || ""}
            onChange={(e) =>
              updateConfig("auth_response_headers", e.currentTarget.value)
            }
          />
          <TextInput
            label="Auth Request Headers"
            description="Comma-separated headers to forward to auth service. Empty = all headers"
            placeholder="Cookie, Authorization"
            value={config.auth_request_headers || ""}
            onChange={(e) =>
              updateConfig("auth_request_headers", e.currentTarget.value)
            }
          />
          <Group grow>
            <NumberInput
              label="Max Body Size (bytes)"
              description="Limit when forwarding body. Default 1MB. -1 = unlimited"
              value={
                config.max_body_size
                  ? parseInt(config.max_body_size)
                  : 1048576
              }
              onChange={(val) =>
                updateConfig(
                  "max_body_size",
                  (val ?? 1048576).toString()
                )
              }
              min={-1}
            />
            <Switch
              label="Trust Forward Header"
              description="Trust X-Forwarded-* from incoming request"
              checked={config.trust_forward_header === "true"}
              onChange={(e) =>
                updateConfig(
                  "trust_forward_header",
                  e.currentTarget.checked ? "true" : "false"
                )
              }
              mt={20}
            />
          </Group>
          <Group grow>
            <Switch
              label="Forward Body"
              description="Forward request body to auth service"
              checked={config.forward_body === "true"}
              onChange={(e) =>
                updateConfig(
                  "forward_body",
                  e.currentTarget.checked ? "true" : "false"
                )
              }
            />
            <Switch
              label="Preserve Request Method"
              description="Use same HTTP method for auth request"
              checked={config.preserve_request_method === "true"}
              onChange={(e) =>
                updateConfig(
                  "preserve_request_method",
                  e.currentTarget.checked ? "true" : "false"
                )
              }
            />
            <Switch
              label="TLS Insecure Skip Verify"
              description="Skip TLS cert verification (dev only)"
              checked={config.tls_insecure_skip_verify === "true"}
              onChange={(e) =>
                updateConfig(
                  "tls_insecure_skip_verify",
                  e.currentTarget.checked ? "true" : "false"
                )
              }
            />
          </Group>
        </Stack>
      );

    case "grpcweb":
      return (
        <Text size="sm" c="dimmed">
          No configuration needed. This middleware automatically converts
          gRPC-Web requests to standard gRPC.
        </Text>
      );

    case "ipfilter":
      return (
        <Stack gap="md">
          <TextInput
            label="Allow List (comma-separated IPs/CIDRs)"
            placeholder="10.0.0.0/8, 192.168.1.1"
            value={config.allow_list || ""}
            onChange={(e) => updateConfig("allow_list", e.currentTarget.value)}
            description="If set, only these IPs are allowed. Empty = allow all (except deny list)."
          />
          <TextInput
            label="Deny List (comma-separated IPs/CIDRs)"
            placeholder="10.0.0.100, 192.168.0.0/24"
            value={config.deny_list || ""}
            onChange={(e) => updateConfig("deny_list", e.currentTarget.value)}
            description="These IPs are always rejected. Takes precedence over allow list."
          />
        </Stack>
      );

    case "cache":
      return (
        <Stack gap="md">
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

    default:
      return (
        <Text size="sm" c="red">
          Unknown middleware type: {type}
        </Text>
      );
  }
}
