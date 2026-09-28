// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Text, Stack, TextInput, NumberInput, Box, Select } from "@mantine/core";
import type { AuthConfig } from "../../../types/gateon";
import type { DatabaseConfig } from "../../../types/gateon";
import { StoredSecretInput } from "../StoredSecretInput";
import { isStoredSecret } from "../../../utils/storedSecret";
import { generateRandomString } from "../../../utils/random";

function inferDriver(
  databaseUrl?: string,
  sqlitePath?: string
): DatabaseConfig["driver"] | null {
  // A connection URL hidden whole says nothing about its driver.
  if (isStoredSecret(databaseUrl)) return null;
  const raw = databaseUrl || sqlitePath || "";
  if (raw.startsWith("postgres")) return "postgres";
  if (raw.startsWith("mysql")) return "mysql";
  if (raw.startsWith("mariadb")) return "mariadb";
  return "sqlite";
}

interface AuthDatabaseFieldsProps {
  auth: AuthConfig;
  onChange: (auth: AuthConfig) => void;
  disabled: boolean;
}

// The user database behind role-based access control.
export function AuthDatabaseFields({ auth, onChange, disabled }: AuthDatabaseFieldsProps) {
  return (
    <Box>
      <Text size="sm" fw={600} mb="xs">
        Database
      </Text>
      <Select
        label="Driver"
        placeholder="Select database"
        data={[
          { value: "sqlite", label: "SQLite" },
          { value: "postgres", label: "PostgreSQL" },
        ]}
        value={
          auth.databaseConfig?.driver ||
          inferDriver(
            auth.databaseUrl,
            auth.sqlitePath
          )
        }
        onChange={(v) =>
          onChange({
            ...auth,
            databaseConfig: {
              ...(auth.databaseConfig || {}),
              driver: (v as DatabaseConfig["driver"]) || "sqlite",
              host: v && v !== "sqlite" ? auth.databaseConfig?.host || "127.0.0.1" : undefined,
              port: v === "postgres" ? 5432 : v === "mysql" || v === "mariadb" ? 3306 : undefined,
              database: v && v !== "sqlite" ? auth.databaseConfig?.database || "gateon" : undefined,
              sslMode: v === "postgres" ? "disable" : undefined,
            },
            databaseUrl: undefined,
            sqlitePath: undefined,
          })
        }
        disabled={disabled}
        radius="md"
        mb="md"
      />
      {isStoredSecret(auth.databaseUrl) && !auth.databaseConfig?.driver && (
        <Text size="xs" c="dimmed" mb="md">
          The gateway connects with a stored database URL, which is hidden because it holds a
          password. It is kept unless you choose a driver here and configure the database instead.
        </Text>
      )}
      {(auth.databaseConfig?.driver === "sqlite" ||
        (!auth.databaseConfig?.driver && !isStoredSecret(auth.databaseUrl))) && (
        <TextInput
          label="SQLite path"
          placeholder="gateon.db"
          disabled={disabled}
          value={
            auth.databaseConfig?.sqlitePath ??
            auth.sqlitePath ??
            (auth.databaseUrl &&
            !auth.databaseUrl.includes("://") &&
            !isStoredSecret(auth.databaseUrl)
              ? auth.databaseUrl
              : "")
          }
          onChange={(e) =>
            onChange({
              ...auth,
              databaseConfig: {
                ...(auth.databaseConfig || {}),
                driver: "sqlite",
                sqlitePath: e.currentTarget.value || "gateon.db",
              },
              databaseUrl: undefined,
              sqlitePath: undefined,
            })
          }
          radius="md"
        />
      )}
      {(auth.databaseConfig?.driver === "postgres" ||
        auth.databaseConfig?.driver === "mysql" ||
        auth.databaseConfig?.driver === "mariadb") && (
        <Stack gap="md">
          <TextInput
            label="Host"
            placeholder="127.0.0.1"
            disabled={disabled}
            value={auth.databaseConfig?.host || ""}
            onChange={(e) =>
              onChange({
                ...auth,
                databaseConfig: {
                  ...(auth.databaseConfig || {}),
                  host: e.currentTarget.value,
                },
              })
            }
            radius="md"
          />
          <NumberInput
            label="Port"
            placeholder={
              auth.databaseConfig?.driver === "postgres"
                ? "5432"
                : "3306"
            }
            min={1}
            max={65535}
            disabled={disabled}
            value={
              auth.databaseConfig?.port ||
              (auth.databaseConfig?.driver === "postgres"
                ? 5432
                : 3306)
            }
            onChange={(v) =>
              onChange({
                ...auth,
                databaseConfig: {
                  ...(auth.databaseConfig || {}),
                  port: typeof v === "string" ? parseInt(v, 10) || 0 : v ?? 0,
                },
              })
            }
            radius="md"
          />
          <TextInput
            label="User"
            placeholder="gateon"
            disabled={disabled}
            value={auth.databaseConfig?.user || ""}
            onChange={(e) =>
              onChange({
                ...auth,
                databaseConfig: {
                  ...(auth.databaseConfig || {}),
                  user: e.currentTarget.value,
                },
              })
            }
            radius="md"
          />
          <StoredSecretInput
            label="Password"
            clearable
            disabled={disabled}
            value={auth.databaseConfig?.password}
            onChange={(password) =>
              onChange({
                ...auth,
                databaseConfig: { ...(auth.databaseConfig || {}), password },
              })
            }
            generate={() => generateRandomString(24)}
            description="Changing the host, port or driver needs the password entered again: a stored password is only sent where it was entered for."
          />
          <TextInput
            label="Database"
            placeholder="gateon"
            disabled={disabled}
            value={auth.databaseConfig?.database || ""}
            onChange={(e) =>
              onChange({
                ...auth,
                databaseConfig: {
                  ...(auth.databaseConfig || {}),
                  database: e.currentTarget.value,
                },
              })
            }
            radius="md"
          />
          {auth.databaseConfig?.driver === "postgres" && (
            <Select
              label="SSL mode"
              data={[
                { value: "disable", label: "disable" },
                { value: "require", label: "require" },
                { value: "verify-ca", label: "verify-ca" },
                { value: "verify-full", label: "verify-full" },
              ]}
              value={auth.databaseConfig?.sslMode || "disable"}
              onChange={(v) =>
                onChange({
                  ...auth,
                  databaseConfig: {
                    ...(auth.databaseConfig || {}),
                    sslMode: v || "disable",
                  },
                })
              }
              disabled={disabled}
              radius="md"
            />
          )}
        </Stack>
      )}
    </Box>
  );
}
