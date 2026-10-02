// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Stack, Select, TextInput, Group, Switch, Divider, Text, ActionIcon, Button } from "@mantine/core";
import { IconPlus, IconTrash } from "@tabler/icons-react";
import { KeyValueList } from "./KeyValueList";
import { StoredSecretInput } from "../settings/StoredSecretInput";
import { isSecretReference, isStoredSecret } from "../../utils/storedSecret";
import { audienceProblem, basicUserProblem, joinUsers, parseUsers } from "./authConfigProblems";

interface AuthConfigEditorProps {
  config: Record<string, string>;
  onChange: (config: Record<string, string>) => void;
}

/**
 * The basic-auth user list, "name:password,...". The gateway returns each
 * stored password as the stored-secret placeholder and keeps it by the user's
 * name (ADR 0033), so every user is a row with a write-only password. A list
 * held as a reference, or returned whole as the placeholder, is one secret.
 */
function BasicUsersEditor({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  if (isStoredSecret(value) || isSecretReference(value)) {
    return <StoredSecretInput label="Users" value={value} onChange={onChange} clearable />;
  }
  const users = parseUsers(value);
  const update = (i: number, next: Partial<{ name: string; password: string }>) =>
    onChange(joinUsers(users.map((u, j) => (i === j ? { ...u, ...next } : u))));
  return (
    <Stack gap="xs">
      <Text size="sm" fw={500}>Users</Text>
      <Text size="xs" c="dimmed">
        Passwords are kept by user name: a renamed user needs its password entered again.
      </Text>
      {users.map((u, i) => (
        <Group key={i} grow align="flex-start">
          <TextInput
            label="Username"
            required
            value={u.name}
            error={u.name.trim() ? undefined : basicUserProblem(u)}
            onChange={(e) => update(i, { name: e.currentTarget.value })}
          />
          <StoredSecretInput
            label="Password"
            required
            value={u.password}
            error={u.name.trim() ? basicUserProblem(u) : undefined}
            onChange={(password) => update(i, { password })}
          />
          <ActionIcon
            color="red"
            variant="light"
            mt={24}
            aria-label={`Remove the user ${u.name}`}
            onClick={() => onChange(joinUsers(users.filter((_, j) => j !== i)))}
          >
            <IconTrash size={16} />
          </ActionIcon>
        </Group>
      ))}
      <Button
        variant="light"
        size="xs"
        leftSection={<IconPlus size={14} />}
        style={{ alignSelf: "flex-start" }}
        onClick={() => onChange(joinUsers([...users, { name: `user${users.length + 1}`, password: "" }]))}
      >
        Add user
      </Button>
    </Stack>
  );
}

function AudienceFields({ config, updateConfig }: { config: Record<string, string>; updateConfig: (key: string, value: string) => void }) {
  const anyAudience = config.allow_any_audience === "true";
  return (
    <>
      <TextInput
        label="Audience"
        required={!anyAudience}
        description="This API's identifier at the provider: the aud a token must carry to be accepted here."
        placeholder="my-api"
        value={config.audience || ""}
        error={audienceProblem(config)}
        onChange={(e) => updateConfig("audience", e.currentTarget.value)}
      />
      <Switch
        label="Accept a token issued for any audience"
        description="Only for a provider that issues tokens to this gateway alone. Any application's token from this provider passes."
        color="red"
        checked={anyAudience}
        onChange={(e) => updateConfig("allow_any_audience", e.currentTarget.checked ? "true" : "false")}
      />
    </>
  );
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
          checked={config.dry_run === "true"}
          onChange={(e) => updateConfig("dry_run", e.currentTarget.checked ? "true" : "false")}
        />
        {(config.type === "jwt" || config.type === "paseto" || config.type === "oidc") && (
          <Switch
            label="Enable Revocation"
            description="Check Redis for revoked tokens (JTI)"
            checked={config.enable_revocation === "true"}
            onChange={(e) => updateConfig("enable_revocation", e.currentTarget.checked ? "true" : "false")}
          />
        )}
      </Group>

      <Group grow>
        <TextInput
          label="Required Scopes"
          description="Comma-separated scopes (e.g. read, write)"
          placeholder="read, write"
          value={config.required_scopes || ""}
          onChange={(e) => updateConfig("required_scopes", e.currentTarget.value)}
        />
        <TextInput
          label="Required Roles"
          description="Comma-separated roles (e.g. admin, editor)"
          placeholder="admin, editor"
          value={config.required_roles || ""}
          onChange={(e) => updateConfig("required_roles", e.currentTarget.value)}
        />
      </Group>

      <TextInput
        label="Custom Error Template"
        description="JSON response if auth fails (e.g. { 'error': 'unauthorized' })"
        placeholder='{ "error": "Unauthorized access", "code": 401 }'
        value={config.error_template || ""}
        onChange={(e) => updateConfig("error_template", e.currentTarget.value)}
      />

      <KeyValueList
        config={config}
        onChange={onChange}
        title="Claim-to-Header Mapping"
        prefix="map_claim_"
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
              checked={config.hashed === "true"}
              onChange={(e) => updateConfig("hashed", e.currentTarget.checked ? "true" : "false")}
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
          <BasicUsersEditor value={config.users || ""} onChange={(v) => updateConfig("users", v)} />
          <Group grow align="flex-start">
            <TextInput
              label="Username (single user)"
              description="Used when the list above is empty"
              placeholder="admin"
              value={config.username || ""}
              onChange={(e) => updateConfig("username", e.currentTarget.value)}
            />
            <StoredSecretInput
              label="Password (single user)"
              placeholder="••••••••"
              value={config.password || ""}
              onChange={(v) => updateConfig("password", v)}
              clearable={!!config.users}
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
            label="JWKS URL"
            description="For RS256/ES256. If set, secret is optional."
            placeholder="https://auth.example.com/.well-known/jwks.json"
            value={config.jwks_url || ""}
            onChange={(e) => updateConfig("jwks_url", e.currentTarget.value)}
          />
          <StoredSecretInput
            label="Secret (required if not using JWKS)"
            description="HS256 shared secret, or GATEON_JWT_SECRET env"
            placeholder="HS256 Secret"
            value={config.secret || ""}
            onChange={(v) => updateConfig("secret", v)}
            clearable={!!config.jwks_url}
          />
          {(config.jwks_url || "").trim() ? (
            <AudienceFields config={config} updateConfig={updateConfig} />
          ) : (
            <TextInput
              label="Audience (optional with a shared secret)"
              placeholder="my-api"
              value={config.audience || ""}
              onChange={(e) => updateConfig("audience", e.currentTarget.value)}
            />
          )}
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
          <AudienceFields config={config} updateConfig={updateConfig} />
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
          <StoredSecretInput
            label="Client Secret"
            description="Or GATEON_OAUTH2_CLIENT_SECRET env. Kept only while the introspection URL stays the same."
            placeholder="••••••••"
            value={config.client_secret || ""}
            onChange={(v) => updateConfig("client_secret", v)}
          />
          <TextInput
            label="Token Type Hint (optional)"
            description="accessToken or refreshToken"
            placeholder="accessToken"
            value={config.token_type_hint || ""}
            onChange={(e) =>
              updateConfig("token_type_hint", e.currentTarget.value)
            }
          />
        </>
      )}
      {config.type === "paseto" && (
        <StoredSecretInput
          label="PASETO Secret (32+ bytes)"
          description="Symmetric key. Or GATEON_PASETO_SECRET env."
          placeholder="32+ character secret"
          value={config.secret || ""}
          onChange={(v) => updateConfig("secret", v)}
        />
      )}
      {renderCommonAuthFields()}
    </Stack>
  );
}
