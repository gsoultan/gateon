// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import React, { useState } from "react";
import {
  Modal,
  Button,
  Text,
  Stack,
  Group,
  TextInput,
  PasswordInput,
  Image,
  Code,
  ThemeIcon,
  rem,
  Alert,
  SimpleGrid,
  Paper,
} from "@mantine/core";
import { IconAlertCircle, IconShieldCheck, IconInfoCircle } from "@tabler/icons-react";
import type { Setup2FAResponse, User } from "../types/gateon";
import { startTwoFactorSetup, verifyTwoFactorCode } from "./twoFactorSetup";

interface TwoFactorModalProps {
  opened: boolean;
  onClose: () => void;
  user: User;
  onSuccess: () => void;
}

interface PasswordStepProps {
  password: string;
  onPasswordChange: (value: string) => void;
  onSubmit: () => void;
  loading: boolean;
  error: string | null;
}

/**
 * The first step of enrolment: the account's current password.
 *
 * The gateway will not start setup on the session alone, because setup hands
 * back a TOTP secret and the session is a cookie that script in the page can
 * ride. A wrong password counts towards the sign-in lockout, so the error says
 * which of the two happened without repeating anything the server wrote.
 */
export const TwoFactorPasswordStep: React.FC<PasswordStepProps> = ({
  password,
  onPasswordChange,
  onSubmit,
  loading,
  error,
}) => (
  <form
    onSubmit={(e) => {
      e.preventDefault();
      onSubmit();
    }}
  >
    <Stack gap="md">
      <Text size="sm">
        Two-factor authentication (2FA) adds an extra layer of security to your account.
        In addition to your password, you'll need to enter a code from an authenticator app.
      </Text>
      <PasswordInput
        label="Current password"
        description="Confirm it's you before an authenticator is linked to this account."
        value={password}
        onChange={(e) => onPasswordChange(e.currentTarget.value)}
        autoComplete="current-password"
        required
        data-autofocus
      />
      {error && (
        <Alert color="red" variant="light" icon={<IconAlertCircle size="1rem" />} role="alert">
          {error}
        </Alert>
      )}
      <Button type="submit" loading={loading} disabled={password.length === 0} fullWidth>
        Continue
      </Button>
    </Stack>
  </form>
);

export const TwoFactorModal: React.FC<TwoFactorModalProps> = ({
  opened,
  onClose,
  user,
  onSuccess,
}) => {
  const [step, setPage] = useState<"intro" | "setup" | "verify" | "success">("intro");
  const [setupData, setSetupData] = useState<Setup2FAResponse | null>(null);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const startSetup = async () => {
    setLoading(true);
    setError(null);
    const outcome = await startTwoFactorSetup(user.id, password);
    // Not kept past the attempt: a refused one is retyped, and an accepted one
    // has no further use.
    setPassword("");
    setLoading(false);
    if (outcome.ok) {
      setSetupData(outcome.data);
      setPage("setup");
    } else {
      setError(outcome.message);
    }
  };

  const verifyCode = async () => {
    setLoading(true);
    setError(null);
    const outcome = await verifyTwoFactorCode(user.id, code, setupData?.challenge ?? "");
    setLoading(false);
    if (outcome.ok) {
      setPage("success");
      onSuccess();
    } else {
      setError(outcome.message);
    }
  };

  const handleClose = () => {
    setPage("intro");
    setSetupData(null);
    setPassword("");
    setCode("");
    setError(null);
    onClose();
  };

  return (
    <Modal
      opened={opened}
      onClose={handleClose}
      title="Two-Factor Authentication"
      size="md"
      radius="md"
    >
      <Stack gap="md">
        {step === "intro" && (
          <TwoFactorPasswordStep
            password={password}
            onPasswordChange={setPassword}
            onSubmit={() => void startSetup()}
            loading={loading}
            error={error}
          />
        )}

        {step === "setup" && setupData && (
          <>
            <Text size="sm" fw={500}>1. Scan this QR Code</Text>
            <Group justify="center">
              <Image src={setupData.qrCodeUrl} maw={200} mx="auto" fit="contain" alt="2FA QR Code" />
            </Group>
            <Text size="xs" c="dimmed" ta="center">
              Or enter secret manually: <Code>{setupData.secret}</Code>
            </Text>

            <Text size="sm" fw={500} mt="md">2. Save your recovery codes</Text>
            <Alert icon={<IconInfoCircle size="1rem" />} color="blue" variant="light">
              <Text size="xs">
                If you lose your device, these codes are the ONLY way to access your account.
              </Text>
            </Alert>
            <Paper withBorder p="xs" bg="var(--mantine-color-gray-0)">
              <SimpleGrid cols={2} spacing="xs">
                {setupData.recoveryCodes.map((c) => (
                  <Code key={c} block>{c}</Code>
                ))}
              </SimpleGrid>
            </Paper>

            <Button onClick={() => setPage("verify")} mt="md">
              I've saved my codes
            </Button>
          </>
        )}

        {step === "verify" && (
          <>
            <Text size="sm">
              Enter the 6-digit code from your authenticator app to verify setup.
            </Text>
            <TextInput
              label="Verification code"
              placeholder="000000"
              value={code}
              onChange={(e) => setCode(e.currentTarget.value)}
              error={error}
              autoComplete="one-time-code"
              inputMode="numeric"
              data-autofocus
            />
            <Button onClick={() => void verifyCode()} loading={loading} disabled={code.length === 0} fullWidth>
              Verify & Enable
            </Button>
            <Button variant="subtle" onClick={() => setPage("setup")} fullWidth>
              Back
            </Button>
          </>
        )}

        {step === "success" && (
          <>
            <Group justify="center">
              <ThemeIcon size={60} radius={60} color="green" variant="light">
                <IconShieldCheck style={{ width: rem(34), height: rem(34) }} />
              </ThemeIcon>
            </Group>
            <Text ta="center" fw={700}>2FA Enabled Successfully!</Text>
            <Text ta="center" size="sm" c="dimmed">
              Your account is now protected with two-factor authentication.
            </Text>
            <Button onClick={handleClose} fullWidth>
              Done
            </Button>
          </>
        )}
      </Stack>
    </Modal>
  );
};
