import {
  Stack,
  TextInput,
  Textarea,
  Switch,
  NumberInput,
  Group,
  Text,
  Button,
  FileButton,
  ActionIcon,
  Divider,
  TagsInput,
} from "@mantine/core";
import { useState } from "react";
import { IconPlus, IconTrash } from "@tabler/icons-react";

import { apiFetch, getCloudflareIPs } from "../../hooks/useGateon";

interface EditorProps {
  config: Record<string, string>;
  updateConfig: (key: string, value: string) => void;
}

export function WAFConfigEditor({ config, updateConfig }: EditorProps) {
  const isEnabled = (key: string) => config[key] !== "false";
  const toggle = (key: string, val: boolean) => updateConfig(key, val ? "true" : "false");

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

      {config.use_crs !== "false" && (
        <>
          <Divider label="Protection Categories" labelPosition="center" />
          <Group grow>
            <Stack gap="xs">
              <Switch
                label="SQL Injection"
                description="Detects common SQL injection attacks"
                checked={isEnabled("sqli")}
                onChange={(e) => toggle("sqli", e.currentTarget.checked)}
              />
              <Switch
                label="Cross-Site Scripting (XSS)"
                description="Detects XSS injection attempts"
                checked={isEnabled("xss")}
                onChange={(e) => toggle("xss", e.currentTarget.checked)}
              />
              <Switch
                label="Local/Remote File Inclusion"
                description="Detects LFI/RFI attacks"
                checked={isEnabled("lfi")}
                onChange={(e) => toggle("lfi", e.currentTarget.checked)}
              />
              <Switch
                label="Remote Code Execution"
                description="Detects RCE and shell commands"
                checked={isEnabled("rce")}
                onChange={(e) => toggle("rce", e.currentTarget.checked)}
              />
            </Stack>
            <Stack gap="xs">
              <Switch
                label="Scanner Detection"
                description="Blocks known vulnerability scanners"
                checked={isEnabled("scanner")}
                onChange={(e) => toggle("scanner", e.currentTarget.checked)}
              />
              <Switch
                label="Protocol Enforcement"
                description="Enforces strict HTTP protocol compliance"
                checked={isEnabled("protocol")}
                onChange={(e) => toggle("protocol", e.currentTarget.checked)}
              />
              <Switch
                label="PHP Injection"
                description="Detects PHP-specific injection attacks"
                checked={isEnabled("php")}
                onChange={(e) => toggle("php", e.currentTarget.checked)}
              />
              <Switch
                label="Java Injection"
                description="Detects Java-specific injection attacks"
                checked={isEnabled("java")}
                onChange={(e) => toggle("java", e.currentTarget.checked)}
              />
            </Stack>
          </Group>

          <Divider label="CRS Settings" labelPosition="center" />
          <NumberInput
            label="Paranoia Level"
            description="CRS paranoia 1-4. Higher = stricter, more false positives. Default: 1"
            value={parseInt(config.paranoia_level) || 1}
            onChange={(val) => updateConfig("paranoia_level", (val ?? 1).toString())}
            min={1}
            max={4}
          />
        </>
      )}

      <Divider label="Advanced" labelPosition="center" />
      <Textarea
        label="Custom Directives"
        description="Coraza/ModSecurity compatible SecLang rules (advanced)"
        placeholder="SecRule ARGS 'foo' 'id:1,deny,status:403'"
        value={config.directives || ""}
        onChange={(e) => updateConfig("directives", e.currentTarget.value)}
        minRows={4}
        autosize
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
  const splitTags = (val: string) => (val || "").split(",").map((s) => s.trim()).filter(Boolean);
  const joinTags = (tags: string[]) => tags.join(", ");

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
      <TagsInput
        label="Methods to Verify"
        description="HTTP methods to verify. Select or type and press Enter."
        placeholder="POST, PUT, PATCH, DELETE"
        data={["POST", "PUT", "PATCH", "DELETE", "GET"]}
        value={splitTags(config.methods)}
        onChange={(val) => updateConfig("methods", joinTags(val))}
        clearable
      />
    </Stack>
  );
}

export function GeoIPConfigEditor({ config, updateConfig }: EditorProps) {
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadSuccess, setUploadSuccess] = useState<string | null>(null);

  const splitTags = (val: string) => (val || "").split(",").map((s) => s.trim()).filter(Boolean);
  const joinTags = (tags: string[]) => tags.join(", ");

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
      <TagsInput
        label="Allow Countries"
        description="ISO 3166-1 alpha-2 codes (e.g. US, GB, DE). Empty = allow all except deny list."
        placeholder="US, GB, DE, FR"
        value={splitTags(config.allow_countries)}
        onChange={(val) => updateConfig("allow_countries", joinTags(val))}
        styles={{ input: { minHeight: 60 } }}
        clearable
      />
      <TagsInput
        label="Deny Countries"
        description="ISO codes to always block. Takes precedence over allow list."
        placeholder="CN, RU"
        value={splitTags(config.deny_countries)}
        onChange={(val) => updateConfig("deny_countries", joinTags(val))}
        styles={{ input: { minHeight: 60 } }}
        clearable
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
  const splitTags = (val: string) => (val || "").split(",").map((s) => s.trim()).filter(Boolean);
  const joinTags = (tags: string[]) => tags.join(", ");

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
      <TagsInput
        label="Methods to Verify"
        description="HTTP methods to verify. Empty = verify all."
        placeholder="POST, PUT"
        data={["POST", "PUT", "PATCH", "DELETE", "GET"]}
        value={splitTags(config.methods)}
        onChange={(val) => updateConfig("methods", joinTags(val))}
        clearable
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

export function XFCCConfigEditor({ config, updateConfig }: EditorProps) {
  return (
    <Stack gap="md">
      <Text size="sm">Extract and forward client certificate details to backend services via X-Forwarded-Client-Cert header.</Text>
      <Switch
        label="Forward By"
        checked={config.forward_by === "true"}
        onChange={(e) => updateConfig("forward_by", e.currentTarget.checked ? "true" : "false")}
      />
      <Switch
        label="Forward Hash"
        checked={config.forward_hash === "true"}
        onChange={(e) => updateConfig("forward_hash", e.currentTarget.checked ? "true" : "false")}
      />
      <Switch
        label="Forward Subject"
        checked={config.forward_subject === "true"}
        onChange={(e) => updateConfig("forward_subject", e.currentTarget.checked ? "true" : "false")}
      />
      <Switch
        label="Forward URI"
        checked={config.forward_uri === "true"}
        onChange={(e) => updateConfig("forward_uri", e.currentTarget.checked ? "true" : "false")}
      />
      <Switch
        label="Forward DNS"
        checked={config.forward_dns === "true"}
        onChange={(e) => updateConfig("forward_dns", e.currentTarget.checked ? "true" : "false")}
      />
    </Stack>
  );
}

export function IPFilterConfigEditor({ config, updateConfig }: EditorProps) {
  const [importing, setImporting] = useState(false);

  const splitTags = (val: string) => (val || "").split(",").map((s) => s.trim()).filter(Boolean);
  const joinTags = (tags: string[]) => tags.join(", ");

  const handleImportCloudflare = async () => {
    setImporting(true);
    try {
      const ips = await getCloudflareIPs();
      const newIps = [...ips.ipv4_cidrs, ...ips.ipv6_cidrs];
      const current = config.allow_list
        ? config.allow_list.split(",").map((s) => s.trim())
        : [];
      const merged = Array.from(new Set([...current, ...newIps]))
        .filter(Boolean)
        .join(", ");
      updateConfig("allow_list", merged);
    } catch (err) {
      console.error("Failed to import Cloudflare IPs:", err);
    } finally {
      setImporting(false);
    }
  };

  return (
    <Stack gap="md">
      <TagsInput
        label="Allow List"
        description="IPs or CIDRs to allow. If set, only these are allowed."
        placeholder="10.0.0.0/8, 192.168.1.1"
        value={splitTags(config.allow_list)}
        onChange={(val) => updateConfig("allow_list", joinTags(val))}
        styles={{ input: { minHeight: 60 } }}
        clearable
      />
      <Group>
        <Button
          variant="light"
          size="xs"
          loading={importing}
          onClick={handleImportCloudflare}
        >
          Import Cloudflare IPs
        </Button>
      </Group>
      <TagsInput
        label="Deny List"
        description="IPs or CIDRs to always block."
        placeholder="10.0.0.100, 192.168.0.0/24"
        value={splitTags(config.deny_list)}
        onChange={(val) => updateConfig("deny_list", joinTags(val))}
        styles={{ input: { minHeight: 60 } }}
        clearable
      />
      <Switch
        label="Trust Cloudflare Headers"
        description="Use CF-Connecting-IP when behind Cloudflare"
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

export function PolicyConfigEditor({ config, onChange }: { config: Record<string, string>; onChange: (config: Record<string, string>) => void }) {
  const rules = Object.entries(config)
    .filter(([k]) => k.startsWith("rule_"))
    .map(([k, v]) => ({
      name: k.replace("rule_", ""),
      expression: v,
      message: config[`message_${k.replace("rule_", "")}`] || "",
    }));

  const updateConfig = (key: string, value: string) => {
    onChange({ ...config, [key]: value });
  };

  const addRule = () => {
    const id = Date.now();
    onChange({
      ...config,
      [`rule_new_rule_${id}`]: "true",
      [`message_new_rule_${id}`]: "",
    });
  };

  const removeRule = (name: string) => {
    const newConfig = { ...config };
    delete newConfig[`rule_${name}`];
    delete newConfig[`message_${name}`];
    onChange(newConfig);
  };

  return (
    <Stack gap="md">
      <Text size="sm">
        Evaluate CEL (Common Expression Language) expressions against the request and auth context.
        Variables: `request.method`, `request.path`, `request.header`, `auth.claims`.
      </Text>
      {rules.map((rule, index) => (
        <Stack key={index} gap="xs" style={{ border: '1px solid var(--mantine-color-gray-2)', padding: '12px', borderRadius: '8px' }}>
          <Group justify="space-between" align="flex-end">
            <TextInput
              label="Rule Name"
              placeholder="e.g. admin_only"
              value={rule.name}
              onChange={(e) => {
                const newName = e.currentTarget.value;
                if (!newName || newName === rule.name) return;
                const newConfig = { ...config };
                delete newConfig[`rule_${rule.name}`];
                delete newConfig[`message_${rule.name}`];
                newConfig[`rule_${newName}`] = rule.expression;
                newConfig[`message_${newName}`] = rule.message;
                onChange(newConfig);
              }}
              style={{ flex: 1 }}
            />
            <ActionIcon color="red" variant="light" onClick={() => removeRule(rule.name)} mb="xs">
              <IconTrash size={16} />
            </ActionIcon>
          </Group>
          <TextInput
            label="CEL Expression"
            placeholder="auth.role == 'admin'"
            value={rule.expression}
            onChange={(e) => updateConfig(`rule_${rule.name}`, e.currentTarget.value)}
          />
          <TextInput
            label="Error Message (optional)"
            placeholder="Access denied: Admin role required"
            value={rule.message}
            onChange={(e) => updateConfig(`message_${rule.name}`, e.currentTarget.value)}
          />
        </Stack>
      ))}
      <Button variant="light" leftSection={<IconPlus size={14} />} onClick={addRule} style={{ alignSelf: 'flex-start' }}>
        Add Rule
      </Button>
    </Stack>
  );
}
