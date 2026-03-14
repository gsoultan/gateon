import { Stack, Select, TextInput, Group } from "@mantine/core";
import { KeyValueList } from "./KeyValueList";

interface AuthConfigEditorProps {
  config: Record<string, string>;
  onChange: (config: Record<string, string>) => void;
}

export function AuthConfigEditor({ config, onChange }: AuthConfigEditorProps) {
  const updateConfig = (key: string, value: string) => {
    onChange({ ...config, [key]: value });
  };

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
          <TextInput
            label="API Key Header"
            description="Header to read API key from. Default: X-API-Key"
            placeholder="X-API-Key"
            value={config.header || ""}
            onChange={(e) => updateConfig("header", e.currentTarget.value)}
          />
          <KeyValueList
            config={config}
            onChange={onChange}
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
            value={config.jwks_url || ""}
            onChange={(e) => updateConfig("jwks_url", e.currentTarget.value)}
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
            value={config.introspection_url || ""}
            onChange={(e) =>
              updateConfig("introspection_url", e.currentTarget.value)
            }
          />
          <TextInput
            label="Client ID"
            placeholder="client-id"
            value={config.client_id || ""}
            onChange={(e) => updateConfig("client_id", e.currentTarget.value)}
          />
          <TextInput
            label="Client Secret"
            description="Or GATEON_OAUTH2_CLIENT_SECRET env"
            type="password"
            placeholder="••••••••"
            value={config.client_secret || ""}
            onChange={(e) =>
              updateConfig("client_secret", e.currentTarget.value)
            }
          />
          <TextInput
            label="Token Type Hint (optional)"
            description="access_token or refresh_token"
            placeholder="access_token"
            value={config.token_type_hint || ""}
            onChange={(e) =>
              updateConfig("token_type_hint", e.currentTarget.value)
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
    </Stack>
  );
}
