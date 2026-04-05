import {
  Stack,
  TextInput,
  Switch,
  NumberInput,
  Group,
  Text,
  Button,
  FileButton,
} from "@mantine/core";
import { useState } from "react";

import { apiFetch } from "../../hooks/useGateon";

interface EditorProps {
  config: Record<string, string>;
  updateConfig: (key: string, value: string) => void;
}

export function WAFConfigEditor({ config, updateConfig }: EditorProps) {
  return (
    <Stack gap="md">
      <Switch
        label="Use OWASP CRS"
        description="Enable OWASP Core Rule Set (recommended)"
        checked={config.use_crs !== "false"}
        onChange={(e) =>
          updateConfig("use_crs", e.currentTarget.checked ? "true" : "false")
        }
      />
      <NumberInput
        label="Paranoia Level"
        description="CRS paranoia 1-4. Higher = stricter, more false positives. Default: 1"
        value={parseInt(config.paranoia_level) || 1}
        onChange={(val) => updateConfig("paranoia_level", (val ?? 1).toString())}
        min={1}
        max={4}
      />
      <TextInput
        label="Custom Directives File"
        description="Optional path to custom SecLang rules (advanced)"
        placeholder="/etc/gateon/waf.conf"
        value={config.directives_file || ""}
        onChange={(e) => updateConfig("directives_file", e.currentTarget.value)}
      />
      <Switch
        label="Trust Cloudflare Headers"
        description="Use CF-Connecting-IP for WAF REMOTE_ADDR"
        checked={config.trust_cloudflare_headers === "true"}
        onChange={(e) =>
          updateConfig(
            "trust_cloudflare_headers",
            e.currentTarget.checked ? "true" : "false"
          )
        }
      />
      <Switch
        label="Audit Only"
        description="Log matched rules but do not block requests (SecRuleEngine DetectionOnly)"
        checked={config.audit_only === "true"}
        onChange={(e) =>
          updateConfig("audit_only", e.currentTarget.checked ? "true" : "false")
        }
      />
    </Stack>
  );
}

export function TurnstileConfigEditor({ config, updateConfig }: EditorProps) {
  return (
    <Stack gap="md">
      <TextInput
        label="Secret Key"
        description="Cloudflare Turnstile secret. Or set GATEON_TURNSTILE_SECRET env"
        placeholder="0x4AAAAAAA..."
        type="password"
        value={config.secret || ""}
        onChange={(e) => updateConfig("secret", e.currentTarget.value)}
      />
      <TextInput
        label="Token Header"
        description="Header containing the token. Default: CF-Turnstile-Response"
        placeholder="CF-Turnstile-Response"
        value={config.header || ""}
        onChange={(e) => updateConfig("header", e.currentTarget.value)}
      />
      <TextInput
        label="Methods to Verify"
        description="Comma-separated HTTP methods. Default: POST,PUT,PATCH,DELETE"
        placeholder="POST, PUT, PATCH, DELETE"
        value={config.methods || ""}
        onChange={(e) => updateConfig("methods", e.currentTarget.value)}
      />
    </Stack>
  );
}

export function GeoIPConfigEditor({ config, updateConfig }: EditorProps) {
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadSuccess, setUploadSuccess] = useState<string | null>(null);

  const handleUpload = async (file: File | null) => {
    if (!file) return;

    setUploading(true);
    setUploadError(null);
    setUploadSuccess(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await apiFetch("/v1/geoip/upload", {
        method: "POST",
        body: formData,
      });
      if (!res.ok) {
        throw new Error(await res.text());
      }
      const data = (await res.json()) as { path?: string };
      if (!data.path) {
        throw new Error("upload response missing path");
      }

      updateConfig("db_path", data.path);
      setUploadSuccess(`Uploaded successfully: ${data.path}`);
    } catch (err: any) {
      setUploadError(err?.message || "Upload failed");
    } finally {
      setUploading(false);
    }
  };

  return (
    <Stack gap="md">
      <TextInput
        label="GeoIP Database Path"
        description="Path to GeoLite2-Country.mmdb. Or set GATEON_GEOIP_DB_PATH env"
        placeholder="/etc/gateon/GeoLite2-Country.mmdb"
        value={config.db_path || ""}
        onChange={(e) => updateConfig("db_path", e.currentTarget.value)}
      />
      <Group gap="xs" align="end">
        <FileButton accept=".mmdb" onChange={handleUpload}>
          {(props) => (
            <Button {...props} loading={uploading} variant="light">
              Upload GeoLite DB
            </Button>
          )}
        </FileButton>
      </Group>
      <Text size="xs" c="dimmed">
        Select a `.mmdb` file to upload it and auto-fill the database path.
      </Text>
      {uploadError && (
        <Text size="sm" c="red">
          {uploadError}
        </Text>
      )}
      {uploadSuccess && (
        <Text size="sm" c="green">
          {uploadSuccess}
        </Text>
      )}
      <TextInput
        label="Allow Countries"
        description="Comma-separated ISO 3166-1 alpha-2 codes (e.g. US,GB,DE). Empty = allow all except deny list."
        placeholder="US, GB, DE, FR"
        value={config.allow_countries || ""}
        onChange={(e) => updateConfig("allow_countries", e.currentTarget.value)}
      />
      <TextInput
        label="Deny Countries"
        description="Comma-separated ISO codes. Takes precedence over allow list."
        placeholder="CN, RU"
        value={config.deny_countries || ""}
        onChange={(e) => updateConfig("deny_countries", e.currentTarget.value)}
      />
      <Switch
        label="Trust Cloudflare Headers"
        description="Use CF-Connecting-IP for client IP"
        checked={config.trust_cloudflare_headers === "true"}
        onChange={(e) =>
          updateConfig(
            "trust_cloudflare_headers",
            e.currentTarget.checked ? "true" : "false"
          )
        }
      />
    </Stack>
  );
}

export function HMACConfigEditor({ config, updateConfig }: EditorProps) {
  return (
    <Stack gap="md">
      <TextInput
        label="Secret"
        description="HMAC secret for signature verification. Or GATEON_HMAC_SECRET env"
        type="password"
        placeholder="webhook-secret"
        value={config.secret || ""}
        onChange={(e) => updateConfig("secret", e.currentTarget.value)}
      />
      <TextInput
        label="Signature Header"
        description="Header containing the HMAC. Default: X-Signature-256"
        placeholder="X-Signature-256"
        value={config.header || ""}
        onChange={(e) => updateConfig("header", e.currentTarget.value)}
      />
      <TextInput
        label="Signature Prefix"
        description="Prefix to strip from header value (e.g. sha256= for GitHub)"
        placeholder="sha256="
        value={config.prefix || ""}
        onChange={(e) => updateConfig("prefix", e.currentTarget.value)}
      />
      <TextInput
        label="Methods to Verify"
        description="Comma-separated. Empty = verify all methods"
        placeholder="POST, PUT"
        value={config.methods || ""}
        onChange={(e) => updateConfig("methods", e.currentTarget.value)}
      />
      <NumberInput
        label="Body Limit (bytes)"
        description="Max body size to read for HMAC. Default: 1MB"
        value={parseInt(config.body_limit) || 1048576}
        onChange={(val) =>
          updateConfig("body_limit", (val ?? 1048576).toString())
        }
        min={1024}
      />
    </Stack>
  );
}
