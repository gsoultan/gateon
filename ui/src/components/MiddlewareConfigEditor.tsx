import {
  Stack,
  TextInput,
  NumberInput,
  Switch,
  Select,
  Group,
  Text,
  FileInput,
} from "@mantine/core";
import {
  IconCheck,
  IconCode,
} from "@tabler/icons-react";
import {
  KeyValueList,
  RatelimitConfigEditor,
  AuthConfigEditor,
  HeadersConfigEditor,
  WAFConfigEditor,
  TurnstileConfigEditor,
  GeoIPConfigEditor,
  HMACConfigEditor,
  CacheConfigEditor,
  BufferingConfigEditor,
  InFlightReqConfigEditor,
  RewriteConfigEditor,
  CORSConfigEditor,
  PrefixConfigEditor,
  StripPrefixConfigEditor,
  StripPrefixRegexConfigEditor,
  ReplacePathConfigEditor,
  ReplacePathRegexConfigEditor,
  XFCCConfigEditor,
  PolicyConfigEditor,
} from "./middleware-config";

interface MiddlewareConfigEditorProps {
  type: string;
  config: Record<string, string>;
  onChange: (config: Record<string, string>) => void;
  wasmBlob?: string;
  onWasmBlobChange?: (blob: string) => void;
}

export function MiddlewareConfigEditor({
  type,
  config,
  onChange,
  wasmBlob,
  onWasmBlobChange,
}: MiddlewareConfigEditorProps) {
  const updateConfig = (key: string, value: string) => {
    onChange({ ...config, [key]: value });
  };

  switch (type) {
    case "ratelimit":
      return <RatelimitConfigEditor config={config} onChange={onChange} />;

    case "inflightreq":
      return <InFlightReqConfigEditor config={config} updateConfig={updateConfig} />;

    case "buffering":
      return <BufferingConfigEditor config={config} updateConfig={updateConfig} />;

    case "auth":
      return <AuthConfigEditor config={config} onChange={onChange} />;

    case "headers":
      return <HeadersConfigEditor config={config} onChange={onChange} />;

    case "rewrite":
      return <RewriteConfigEditor config={config} updateConfig={updateConfig} onChange={onChange} />;

    case "addprefix":
      return <PrefixConfigEditor config={config} updateConfig={updateConfig} />;

    case "stripprefix":
      return <StripPrefixConfigEditor config={config} updateConfig={updateConfig} />;

    case "stripprefixregex":
      return <StripPrefixRegexConfigEditor config={config} updateConfig={updateConfig} />;

    case "replacepath":
      return <ReplacePathConfigEditor config={config} updateConfig={updateConfig} />;

    case "replacepathregex":
      return <ReplacePathRegexConfigEditor config={config} updateConfig={updateConfig} />;

    case "cors":
      return <CORSConfigEditor config={config} updateConfig={updateConfig} />;

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
            config={config}
            onChange={onChange}
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
          label="Route Name Override (Optional)"
          placeholder="custom-name"
          value={config.route || config.route_id || ""}
          onChange={(e) => updateConfig("route", e.currentTarget.value)}
        />
      );

    case "compress":
      return (
        <Stack gap="md">
          <Select
            label="Compression Algorithm"
            description="Choose how responses are compressed. Auto prefers Brotli when supported."
            data={[
              { value: "auto", label: "Auto (prefer Brotli, fallback Gzip)" },
              { value: "gzip", label: "Gzip" },
              { value: "br", label: "Brotli" },
            ]}
            value={config.algorithm || "auto"}
            onChange={(val) => updateConfig("algorithm", val || "auto")}
            allowDeselect={false}
          />
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
        <Stack gap="xs">
          <Text size="sm" c="dimmed">
            Required for grpc routes when clients run in the browser. Converts
            gRPC-Web requests to standard gRPC before proxying. No configuration
            needed.
          </Text>
          <Text size="xs" c="dimmed">
            Add this middleware to grpc routes that will be called from web apps
            (e.g. via @improbable-eng/grpc-web). Without it, gRPC-Web requests
            return 415.
          </Text>
        </Stack>
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
          <Switch
            label="Trust Cloudflare Headers"
            description="Use CF-Connecting-IP when behind Cloudflare"
            checked={config.trust_cloudflare_headers === "true"}
            onChange={(e) =>
              updateConfig(
                "trust_cloudflare_headers",
                e.currentTarget.checked ? "true" : "false",
              )
            }
          />
        </Stack>
      );

    case "waf":
      return <WAFConfigEditor config={config} updateConfig={updateConfig} />;

    case "turnstile":
      return <TurnstileConfigEditor config={config} updateConfig={updateConfig} />;

    case "geoip":
      return <GeoIPConfigEditor config={config} updateConfig={updateConfig} />;

    case "hmac":
      return <HMACConfigEditor config={config} updateConfig={updateConfig} />;

    case "xfcc":
      return <XFCCConfigEditor config={config} updateConfig={updateConfig} />;

    case "policy":
      return <PolicyConfigEditor config={config} onChange={onChange} />;

    case "cache":
      return <CacheConfigEditor config={config} updateConfig={updateConfig} />;

    case "transform":
      return (
        <Stack gap="md">
          <TextInput
            label="Content-Type Filter (Optional)"
            placeholder="application/json"
            value={config.content_type || ""}
            onChange={(e) => updateConfig("content_type", e.currentTarget.value)}
            description="Only transform bodies with this content type (substring match)"
          />
          <Group grow>
            <TextInput
              label="Request Search"
              placeholder="foo"
              value={config.request_search || ""}
              onChange={(e) =>
                updateConfig("request_search", e.currentTarget.value)
              }
            />
            <TextInput
              label="Request Replace"
              placeholder="bar"
              value={config.request_replace || ""}
              onChange={(e) =>
                updateConfig("request_replace", e.currentTarget.value)
              }
            />
          </Group>
          <Group grow>
            <TextInput
              label="Response Search"
              placeholder="apple"
              value={config.response_search || ""}
              onChange={(e) =>
                updateConfig("response_search", e.currentTarget.value)
              }
            />
            <TextInput
              label="Response Replace"
              placeholder="orange"
              value={config.response_replace || ""}
              onChange={(e) =>
                updateConfig("response_replace", e.currentTarget.value)
              }
            />
          </Group>
        </Stack>
      );

    case "wasm":
      return (
        <Stack gap="md">
          <Text size="sm">
            WASM Middleware allows you to run custom logic in a sandboxed WebAssembly environment.
            The module should export a `handle()` function that interacts with the HTTP request.
          </Text>
          <FileInput
            label="WASM Module Binary"
            description="Upload your .wasm module"
            placeholder="Select .wasm file"
            accept=".wasm"
            leftSection={<IconCode size={14} />}
            onChange={async (file) => {
              if (file && onWasmBlobChange) {
                const reader = new FileReader();
                reader.onload = (e) => {
                  const arr = new Uint8Array(e.target?.result as ArrayBuffer);
                  // Convert to base64 string
                  let binary = "";
                  for (let i = 0; i < arr.byteLength; i++) {
                    binary += String.fromCharCode(arr[i]);
                  }
                  onWasmBlobChange(window.btoa(binary));
                };
                reader.readAsArrayBuffer(file);
              }
            }}
          />
          {wasmBlob && (
            <Group gap="xs">
              <IconCheck size={14} color="green" />
              <Text size="xs" c="green">
                Module uploaded ({Math.round((wasmBlob.length * 0.75) / 1024)} KB)
              </Text>
            </Group>
          )}
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
