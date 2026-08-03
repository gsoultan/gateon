import { Stack, Select, TextInput, Group, Switch, Divider, Title, Text } from "@mantine/core";
import { KeyValueList } from "./KeyValueList";

interface AuthConfigEditorProps {
  config: Record<string, string>;
  onChange: (config: Record<string, string>) => void;
}

export function AuthConfigEditor({ config, onChange }: AuthConfigEditorProps) {
  const updateConfig = (key: string, value: string) => {
    onChange({ ...config, [key]: value });
  };

  const renderCommonAuthFields = () => (
    <>
      <Divider label="Advanced & Authorization" labelPosition="center" my="sm" />
      <Group grow>
        <Switch
          label="Dry Run Mode"
          description="Validate but do not block request if auth fails"
          checked={config.dryRun === "true"}
          onChange={(e) => updateConfig("dryRun", e.currentTarget.checked ? "true" : "false")}
        />
        {(config.type === "jwt" || config.type === "paseto" || config.type === "oidc") && (
          <Switch
            label="Enable Revocation"
            description="Check Redis for revoked tokens (JTI)"
            checked={config.revocationEnabled === "true"}
            onChange={(e) => updateConfig("revocationEnabled", e.currentTarget.checked ? "true" : "false")}
          />
        )}
      </Group>

      <Group grow>
        <TextInput
          label="Required Scopes"
          description="Comma-separated scopes (e.g. read, write)"
          placeholder="read, write"
          value={config.requiredScopes || ""}
          onChange={(e) => updateConfig("requiredScopes", e.currentTarget.value)}
        />
        <TextInput
          label="Required Roles"
          description="Comma-separated roles (e.g. admin, editor)"
          placeholder="admin, editor"
          value={config.requiredRoles || ""}
          onChange={(e) => updateConfig("requiredRoles", e.currentTarget.value)}
        />
      </Group>

      <TextInput
        label="Custom Error Template"
        description="JSON response if auth fails (e.g. { 'error': 'unauthorized' })"
        placeholder='{ "error": "Unauthorized access", "code": 401 }'
        value={config.errorTemplate || ""}
        onChange={(e) => updateConfig("errorTemplate", e.currentTarget.value)}
      />

      <KeyValueList
        config={config}
        onChange={onChange}
        title="Claim-to-Header Mapping"
        prefix="claim_"
        placeholderKey="email"
        placeholderValue="X-User-Email"
        keyLabel="JWT/Token Claim"
        valueLabel="Request Header"
      />
    </>
  );

  return (
    <Stack gap="md">
      <Select
        label="Authentication Type"
        data={[
          { label: "JWT", value: "jwt" },
          { label: "OIDC (OpenID Connect)", value: "oidc" },
          { label: "OAuth 2.0 Introspection", value: "oauth2" },
          { label: "PASETO", value: "paseto" },
          { label: "API Key", value: "apikey" },
          { label: "Basic Auth", value: "basic" },
        ]}
        value={config.type || "jwt"}
        onChange={(val) => updateConfig("type", val || "jwt")}
      />
      {config.type === "apikey" && (
        <>
          <Group grow align="end">
            <TextInput
              label="API Key Header"
              description="Header to read API key from. Default: X-API-Key"
              placeholder="X-API-Key"
              value={config.header || ""}
              onChange={(e) => updateConfig("header", e.currentTarget.value)}
            />
            <Switch
              label="Hashed Keys"
              description="Store and compare SHA-256 hashes (secure)"
              checked={config.hashedKeys === "true"}
              onChange={(e) => updateConfig("hashedKeys", e.currentTarget.checked ? "true" : "false")}
              mb="xs"
            />
          </Group>
          <KeyValueList
            config={config}
            onChange={onChange}
            title="API Keys"
            prefix="key_"
            placeholderKey="actual-api-key"
            placeholderValue="tenant-id-or-name"
            keyLabel="API Key (Secret)"
            valueLabel="Tenant ID / Label"
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
              onChange={(e) => updateConfig("username", e.currentTarget.value)}
            />
            <TextInput
              label="Password (single user)"
              type="password"
              placeholder="••••••••"
              value={config.password || ""}
              onChange={(e) => updateConfig("password", e.currentTarget.value)}
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
            onChange={(e) => updateConfig("audience", e.currentTarget.value)}
          />
          <TextInput
            label="JWKS URL"
            description="For RS256/ES256. If set, secret is optional."
            placeholder="https://auth.example.com/.well-known/jwks.json"
            value={config.jwksUrl || ""}
            onChange={(e) => updateConfig("jwksUrl", e.currentTarget.value)}
          />
          <TextInput
            label="Secret (required if not using JWKS)"
            description="HS256 shared secret, or GATEON_JWT_SECRET env"
            placeholder="HS256 Secret"
            type="password"
            value={config.secret || ""}
            onChange={(e) => updateConfig("secret", e.currentTarget.value)}
          />
        </>
      )}
      {config.type === "oidc" && (
        <>
          <TextInput
            label="Issuer URL"
            description="OIDC provider (e.g. Auth0, Keycloak)"
            placeholder="https://auth.example.com"
            value={config.issuer || ""}
            onChange={(e) => updateConfig("issuer", e.currentTarget.value)}
          />
          <TextInput
            label="Audience (optional)"
            placeholder="my-api"
            value={config.audience || ""}
            onChange={(e) => updateConfig("audience", e.currentTarget.value)}
          />
        </>
      )}
      {config.type === "oauth2" && (
        <>
          <TextInput
            label="Introspection URL"
            description="RFC 7662 token introspection (required)"
            placeholder="https://auth.example.com/oauth/introspect"
            value={config.introspectionUrl || ""}
            onChange={(e) =>
              updateConfig("introspectionUrl", e.currentTarget.value)
            }
          />
          <TextInput
            label="Client ID"
            placeholder="client-id"
            value={config.clientId || ""}
            onChange={(e) => updateConfig("clientId", e.currentTarget.value)}
          />
          <TextInput
            label="Client Secret"
            description="Or GATEON_OAUTH2_CLIENT_SECRET env"
            type="password"
            placeholder="••••••••"
            value={config.clientSecret || ""}
            onChange={(e) =>
              updateConfig("clientSecret", e.currentTarget.value)
            }
          />
          <TextInput
            label="Token Type Hint (optional)"
            description="accessToken or refreshToken"
            placeholder="accessToken"
            value={config.tokenTypeHint || ""}
            onChange={(e) =>
              updateConfig("tokenTypeHint", e.currentTarget.value)
            }
          />
        </>
      )}
      {config.type === "paseto" && (
        <TextInput
          label="PASETO Secret (32+ bytes)"
          description="Symmetric key. Or GATEON_PASETO_SECRET env."
          type="password"
          placeholder="32+ character secret"
          value={config.secret || ""}
          onChange={(e) => updateConfig("secret", e.currentTarget.value)}
        />
      )}
      {renderCommonAuthFields()}
    </Stack>
  );
}
