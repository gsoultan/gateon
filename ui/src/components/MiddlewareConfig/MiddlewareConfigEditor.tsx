// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import {
  Stack,
  TextInput,
  NumberInput,
  Switch,
  Select,
  Group,
  Text,
  FileInput,
  TagsInput,
} from "@mantine/core";
import {
  IconCheck,
  IconCode,
} from "@tabler/icons-react";
import { KeyValueList } from "./KeyValueList";
import { RatelimitConfigEditor } from "./RatelimitConfigEditor";
import { AuthConfigEditor } from "./AuthConfigEditor";
import { HeadersConfigEditor } from "./HeadersConfigEditor";
import {
  WAFConfigEditor,
  TurnstileConfigEditor,
  GeoIPConfigEditor,
  HMACConfigEditor,
  FileSecurityConfigEditor,
  XFCCConfigEditor,
  PolicyConfigEditor,
  IPFilterConfigEditor,
  BotManagementConfigEditor,
  SchemaValidationConfigEditor,
  HoneypotConfigEditor,
  RequestIDConfigEditor,
  OIDCConfigEditor,
  SecurityHeadersConfigEditor,
} from "./SecurityConfigEditors";
import {
  BufferingConfigEditor,
  InFlightReqConfigEditor,
  CacheConfigEditor,
} from "./TrafficConfigEditors";
import {
  RewriteConfigEditor,
  CORSConfigEditor,
  PrefixConfigEditor,
  StripPrefixConfigEditor,
  StripPrefixRegexConfigEditor,
  ReplacePathConfigEditor,
  ReplacePathRegexConfigEditor,
  CORS_PRESETS,
} from "./MiscConfigEditors";

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

    case "forwardedheaders":
      return (
        <Stack gap="md">
          <Select
            label="X-Forwarded-Proto"
            description="Force the scheme forwarded to the backend. Leave as Auto to derive it from TLS / trusted proxies."
            value={config.proto || ""}
            onChange={(val) => updateConfig("proto", val || "")}
            data={[
              { label: "Auto (derive)", value: "" },
              { label: "https", value: "https" },
              { label: "http", value: "http" },
            ]}
          />
          <Switch
            label="Trust inbound X-Forwarded-Proto"
            description="Honor the inbound X-Forwarded-Proto on this route even when the peer is outside GATEON_TRUSTED_PROXIES. Ignored when a scheme is forced above."
            checked={config.trustForwardHeader === "true"}
            onChange={(e) =>
              updateConfig("trustForwardHeader", e.currentTarget.checked ? "true" : "false")
            }
          />
        </Stack>
      );

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
      return <CORSConfigEditor config={config} updateConfig={updateConfig} onChange={onChange} />;

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
      const splitTags = (val: string) => (val || "").split(",").map((s) => s.trim()).filter(Boolean);
      const joinTags = (tags: string[]) => tags.join(", ");

      return (
        <Stack gap="md">
          <TagsInput
            label="Status Codes"
            placeholder="404, 500, 503"
            value={splitTags(config.statusCodes)}
            onChange={(val) => updateConfig("statusCodes", joinTags(val))}
            description="HTTP status codes that should trigger custom error pages."
            clearable
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
          value={config.route || config.routeId || ""}
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
            value={parseInt(config.minResponseBodyBytes) || 1024}
            onChange={(val) =>
              updateConfig(
                "minResponseBodyBytes",
                (val ?? 1024).toString()
              )
            }
            min={0}
          />
          <TextInput
            label="Excluded Content-Types"
            description="Comma-separated; never compress these (e.g. image/png,image/jpeg)"
            placeholder="image/png, image/jpeg, image/gif"
            value={config.excludedContentTypes || ""}
            onChange={(e) =>
              updateConfig("excludedContentTypes", e.currentTarget.value)
            }
          />
          <TextInput
            label="Included Content-Types"
            description="If set, only compress these; leave empty to compress all except excluded"
            placeholder="text/html, application/json"
            value={config.includedContentTypes || ""}
            onChange={(e) =>
              updateConfig("includedContentTypes", e.currentTarget.value)
            }
          />
          <NumberInput
            label="Max Buffer (bytes)"
            description="Responses larger than this bypass compression (stream through). Default: 10MB"
            value={
              parseInt(config.maxBufferBytes) || 10 * 1024 * 1024
            }
            onChange={(val) =>
              updateConfig(
                "maxBufferBytes",
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
            value={config.authResponseHeaders || ""}
            onChange={(e) =>
              updateConfig("authResponseHeaders", e.currentTarget.value)
            }
          />
          <TextInput
            label="Auth Request Headers"
            description="Comma-separated headers to forward to auth service. Empty = all headers"
            placeholder="Cookie, Authorization"
            value={config.authRequestHeaders || ""}
            onChange={(e) =>
              updateConfig("authRequestHeaders", e.currentTarget.value)
            }
          />
          <Group grow>
            <NumberInput
              label="Max Body Size (bytes)"
              description="Limit when forwarding body. Default 1MB. -1 = unlimited"
              value={
                config.maxBodySize
                  ? parseInt(config.maxBodySize)
                  : 1048576
              }
              onChange={(val) =>
                updateConfig(
                  "maxBodySize",
                  (val ?? 1048576).toString()
                )
              }
              min={-1}
            />
            <Switch
              label="Trust Forward Header"
              description="Trust X-Forwarded-* from incoming request"
              checked={config.trustForwardHeader === "true"}
              onChange={(e) =>
                updateConfig(
                  "trustForwardHeader",
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
              checked={config.forwardBody === "true"}
              onChange={(e) =>
                updateConfig(
                  "forwardBody",
                  e.currentTarget.checked ? "true" : "false"
                )
              }
            />
            <Switch
              label="Preserve Request Method"
              description="Use same HTTP method for auth request"
              checked={config.preserveRequestMethod === "true"}
              onChange={(e) =>
                updateConfig(
                  "preserveRequestMethod",
                  e.currentTarget.checked ? "true" : "false"
                )
              }
            />
            <Switch
              label="TLS Insecure Skip Verify"
              description="Skip TLS cert verification (dev only)"
              checked={config.tlsInsecureSkipVerify === "true"}
              onChange={(e) =>
                updateConfig(
                  "tlsInsecureSkipVerify",
                  e.currentTarget.checked ? "true" : "false"
                )
              }
            />
          </Group>
        </Stack>
      );

    case "grpcweb":
      const splitGrpcTags = (val: string) => (val || "").split(",").map((s) => s.trim()).filter(Boolean);
      const joinGrpcTags = (tags: string[]) => tags.join(", ");

      const applyGrpcPreset = (presetName: string) => {
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
          <Text size="sm" c="dimmed">
            Required for grpc routes when clients run in the browser. Converts
            gRPC-Web requests to standard gRPC before proxying.
          </Text>
          <Select
            label="gRPC-Web Preset"
            placeholder="Select a preset"
            data={[
              { value: "grpc-web", label: "Standard gRPC-Web" },
              { value: "permissive", label: "Permissive (Allow All)" },
            ]}
            value={config.preset || ""}
            onChange={(val) => applyGrpcPreset(val || "")}
            clearable
          />
          <TagsInput
            label="Allowed Origins"
            placeholder="*, https://example.com"
            value={splitGrpcTags(config.allowedOrigins)}
            onChange={(val) => updateConfig("allowedOrigins", joinGrpcTags(val))}
            description="CORS allowed origins for gRPC-Web requests."
            styles={{ input: { minHeight: 60 } }}
            clearable
          />
          <Group grow>
            <NumberInput
              label="Max Age (seconds)"
              value={parseInt(config.maxAge) || 86400}
              onChange={(val) => updateConfig("maxAge", (val ?? 86400).toString())}
              min={0}
            />
            <Switch
              label="Allow Credentials"
              checked={config.allowCredentials === "true"}
              onChange={(e) =>
                updateConfig(
                  "allowCredentials",
                  e.currentTarget.checked ? "true" : "false"
                )
              }
              mt="xl"
            />
          </Group>
        </Stack>
      );

    case "ipfilter":
      return <IPFilterConfigEditor config={config} updateConfig={updateConfig} />;

    case "waf":
      return <WAFConfigEditor config={config} updateConfig={updateConfig} />;

    case "fileSecurity":
      return <FileSecurityConfigEditor config={config} updateConfig={updateConfig} />;

    case "oidc":
      return <OIDCConfigEditor config={config} updateConfig={updateConfig} />;

    case "securityHeaders":
      return <SecurityHeadersConfigEditor config={config} updateConfig={updateConfig} />;

    case "botManagement":
      return <BotManagementConfigEditor config={config} updateConfig={updateConfig} />;

    case "schemaValidation":
      return <SchemaValidationConfigEditor config={config} updateConfig={updateConfig} />;

    case "honeypot":
      return <HoneypotConfigEditor config={config} updateConfig={updateConfig} />;

    case "requestId":
      return <RequestIDConfigEditor />;

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
            value={config.contentType || ""}
            onChange={(e) => updateConfig("contentType", e.currentTarget.value)}
            description="Only transform bodies with this content type (substring match)"
          />
          <Group grow>
            <TextInput
              label="Request Search"
              placeholder="foo"
              value={config.requestSearch || ""}
              onChange={(e) =>
                updateConfig("requestSearch", e.currentTarget.value)
              }
            />
            <TextInput
              label="Request Replace"
              placeholder="bar"
              value={config.requestReplace || ""}
              onChange={(e) =>
                updateConfig("requestReplace", e.currentTarget.value)
              }
            />
          </Group>
          <Group grow>
            <TextInput
              label="Response Search"
              placeholder="apple"
              value={config.responseSearch || ""}
              onChange={(e) =>
                updateConfig("responseSearch", e.currentTarget.value)
              }
            />
            <TextInput
              label="Response Replace"
              placeholder="orange"
              value={config.responseReplace || ""}
              onChange={(e) =>
                updateConfig("responseReplace", e.currentTarget.value)
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
