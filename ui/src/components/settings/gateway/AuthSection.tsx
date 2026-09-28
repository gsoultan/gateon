// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Text, Stack, Divider, Switch, Alert, Box } from "@mantine/core";
import { IconInfoCircle } from "@tabler/icons-react";
import type { AuthConfig } from "../../../types/gateon";
import { StoredSecretInput, type SecretReplaceConfirm } from "../StoredSecretInput";
import { generateRandomString } from "../../../utils/random";
import { AuthDatabaseFields } from "./AuthDatabaseFields";

// What saving a new session key does, said before it can be typed. Every
// session is signed with this key; replacing it is how a key that may have
// leaked stops working, and it takes effect when the settings are saved.
const SESSION_KEY_ROTATION: SecretReplaceConfirm = {
  title: "Replace the session signing key?",
  consequences:
    "When you save, every session ends at once -- everyone, you included, signs in again. " +
    "Two-factor enrolments are kept. Other gateway instances that share this user database " +
    "keep the old key until they are given the new one and restarted, and until then " +
    "sessions and two-factor sign-ins through them fail.",
  confirmLabel: "Replace the key and sign everyone out on save",
};

interface AuthSectionProps {
  auth: AuthConfig;
  onChange: (auth: AuthConfig) => void;
  disabled: boolean;
}

// Role-based access control for the control plane: the key that signs every
// session, and the database the users live in.
export function AuthSection({ auth, onChange, disabled }: AuthSectionProps) {
  return (
    <Box>
      <Divider
        label={
          <Text size="xs" fw={800}>
            SECURITY (PASETO + Database)
          </Text>
        }
        labelPosition="left"
        mb="md"
      />
      <Stack gap="md">
        <Switch
          label="Enable Role-Based Access Control (PASETO)"
          checked={auth.enabled || false}
          disabled={disabled}
          onChange={(e) =>
            onChange({
              ...auth,
              enabled: e.currentTarget.checked,
            })
          }
        />
        {auth.enabled && (
          <Stack gap="md">
            <StoredSecretInput
              label="PASETO Symmetric Key"
              placeholder="32 characters minimum"
              disabled={disabled}
              value={auth.pasetoSecret}
              onChange={(pasetoSecret) =>
                onChange({ ...auth, pasetoSecret })
              }
              generate={() => generateRandomString(32)}
              confirm={SESSION_KEY_ROTATION}
            />
            <AuthDatabaseFields auth={auth} onChange={onChange} disabled={disabled} />
            <Alert
              icon={<IconInfoCircle size={16} />}
              color="blue"
              variant="light"
              radius="md"
            >
              Sensitive values (database URL, password) are encrypted in
              global.json when GATEON_ENCRYPTION_KEY is set. Changing the
              secret key invalidates all sessions.
            </Alert>
          </Stack>
        )}
      </Stack>
    </Box>
  );
}
