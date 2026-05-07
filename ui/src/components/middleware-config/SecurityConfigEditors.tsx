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
                label="NodeJS Attacks"
                description="Detects NodeJS-specific injection attacks"
                checked={isEnabled("nodejs")}
                onChange={(e) => toggle("nodejs", e.currentTarget.checked)}
              />
              <Switch
                label="Java Injection"
                description="Detects Java-specific injection attacks"
                checked={isEnabled("java")}
                onChange={(e) => toggle("java", e.currentTarget.checked)}
              />
              <Switch
                label="WordPress Protection"
                description="Detects WP-specific attacks and probes"
                checked={isEnabled("wordpress")}
                onChange={(e) => toggle("wordpress", e.currentTarget.checked)}
              />
            </Stack>
          </Group>

          <Divider label="Advanced Protections" labelPosition="center" />
          <Group grow>
            <Stack gap="xs">
              <Switch
                label="IP Reputation"
                description="Block requests from known malicious IPs"
                checked={config.ip_reputation === "true"}
                onChange={(e) => updateConfig("ip_reputation", e.currentTarget.checked ? "true" : "false")}
              />
              <Switch
                label="DOS Protection"
                description="Basic HTTP-level DOS protection rules"
                checked={config.dos_protection === "true"}
                onChange={(e) => updateConfig("dos_protection", e.currentTarget.checked ? "true" : "false")}
              />
              <Switch
                label="Malware Detection"
                description="Detect common malware and web shell patterns"
                checked={config.malware_detection === "true"}
                onChange={(e) => updateConfig("malware_detection", e.currentTarget.checked ? "true" : "false")}
              />
            </Stack>
            <Stack gap="xs">
              <Switch
                label="Ransomware Detection"
                description="Detect ransomware file extension uploads"
                checked={config.ransomware_detection === "true"}
                onChange={(e) => updateConfig("ransomware_detection", e.currentTarget.checked ? "true" : "false")}
              />
              <Switch
                label="Data Loss Prevention (DLP)"
                description="Detect sensitive data leakage (CC, SSN) in responses"
                checked={config.dlp === "true"}
                onChange={(e) => updateConfig("dlp", e.currentTarget.checked ? "true" : "false")}
              />
            </Stack>
          </Group>

          <Divider label="CRS Settings" labelPosition="center" />
          <Group grow>
            <NumberInput
              label="Paranoia Level"
              description="CRS paranoia 1-4. Higher = stricter."
              value={parseInt(config.paranoia_level) || 1}
              onChange={(val) => updateConfig("paranoia_level", (val ?? 1).toString())}
              min={1}
              max={4}
            />
            <NumberInput
              label="Anomaly Threshold"
              description="Score required to block. Default: 5"
              value={parseInt(config.anomaly_threshold) || 5}
              onChange={(val) => updateConfig("anomaly_threshold", (val ?? 5).toString())}
              min={1}
            />
          </Group>

          <Divider label="Body Limits" labelPosition="center" />
          <Group grow>
            <NumberInput
              label="Request Body Limit"
              description="Max request body size in bytes. 0 = unlimited."
              value={parseInt(config.request_body_limit) || 0}
              onChange={(val) => updateConfig("request_body_limit", (val ?? 0).toString())}
              min={0}
            />
            <NumberInput
              label="Response Body Limit"
              description="Max response body size in bytes. 0 = unlimited."
              value={parseInt(config.response_body_limit) || 0}
              onChange={(val) => updateConfig("response_body_limit", (val ?? 0).toString())}
              min={0}
            />
          </Group>

          <Divider label="Audit Logging" labelPosition="center" />
          <Stack gap="xs">
            <TextInput
              label="Audit Log Path"
              description="File path for Coraza audit logs (e.g. /var/log/gateon/waf_audit.log)"
              placeholder="/var/log/gateon/waf_audit.log"
              value={config.audit_log_path || ""}
              onChange={(e) => updateConfig("audit_log_path", e.currentTarget.value)}
            />
            <Switch
              label="Relevant Only"
              description="Only log 'relevant' events (e.g. those that triggered a rule)"
              checked={config.audit_log_relevant_only === "true"}
              onChange={(e) => updateConfig("audit_log_relevant_only", e.currentTarget.checked ? "true" : "false")}
            />
          </Stack>
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

export function BotManagementConfigEditor({ config, updateConfig }: EditorProps) {
  const isEnabled = (key: string) => config[key] === "true";
  const toggle = (key: string, val: boolean) => updateConfig(key, val ? "true" : "false");

  return (
    <Stack gap="md">
      <Switch
        label="Browser Integrity Check"
        description="Verify request is from a legitimate browser using Sec-Fetch-* headers"
        checked={isEnabled("enable_browser_integrity")}
        onChange={(e) => toggle("enable_browser_integrity", e.currentTarget.checked)}
      />
      <Switch
        label="JS Challenge"
        description="Serve a non-interactive JS challenge to verify browser capability"
        checked={isEnabled("enable_js_challenge")}
        onChange={(e) => toggle("enable_js_challenge", e.currentTarget.checked)}
      />
      <NumberInput
        label="Challenge Timeout"
        description="How long a solved challenge remains valid (seconds). Default: 3600"
        value={parseInt(config.challenge_timeout) || 3600}
        onChange={(val) => updateConfig("challenge_timeout", (val ?? 3600).toString())}
        min={60}
      />
      <TextInput
        label="Secret Key"
        description="Secret used for signing challenge tokens"
        placeholder="gateon-default-secret"
        type="password"
        value={config.secret_key || ""}
        onChange={(e) => updateConfig("secret_key", e.currentTarget.value)}
      />
    </Stack>
  );
}

export function SchemaValidationConfigEditor({ config, updateConfig }: EditorProps) {
  return (
    <Stack gap="md">
      <Textarea
        label="JSON Schema"
        description="JSON Schema to validate request bodies against"
        placeholder='{ "type": "object", "properties": { "id": { "type": "integer" } } }'
        value={config.schema || ""}
        onChange={(e) => updateConfig("schema", e.currentTarget.value)}
        minRows={10}
        autosize
        styles={{ input: { fontFamily: "monospace" } }}
      />
    </Stack>
  );
}

export function HoneypotConfigEditor({ config, updateConfig }: EditorProps) {
  const splitTags = (val: string) => (val || "").split(",").map((s) => s.trim()).filter(Boolean);
  const joinTags = (tags: string[]) => tags.join(", ");

  return (
    <Stack gap="md">
      <TagsInput
        label="Trap Paths"
        description="Requests to these paths will immediately block the source IP"
        placeholder="/.env, /wp-admin.php, /config.php"
        value={splitTags(config.paths)}
        onChange={(val) => updateConfig("paths", joinTags(val))}
        clearable
      />
    </Stack>
  );
}

export function RequestIDConfigEditor() {
  return (
    <Text size="sm" c="dimmed">
      Automatically generates and injects a unique X-Request-ID header for each request. No configuration required.
    </Text>
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
