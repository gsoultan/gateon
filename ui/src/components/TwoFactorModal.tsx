import React, { useState } from "react";
import {
  Modal,
  Button,
  Text,
  Stack,
  Group,
  TextInput,
  Image,
  Code,
  List,
  ThemeIcon,
  rem,
  Alert,
  SimpleGrid,
} from "@mantine/core";
import { IconCheck, IconCopy, IconShieldCheck, IconInfoCircle } from "@tabler/icons-react";
import { apiFetch } from "../hooks/useGateon";
import type { Setup2FAResponse, User } from "../types/gateon";

interface TwoFactorModalProps {
  opened: boolean;
  onClose: () => void;
  user: User;
  onSuccess: () => void;
}

export const TwoFactorModal: React.FC<TwoFactorModalProps> = ({
  opened,
  onClose,
  user,
  onSuccess,
}) => {
  const [step, setPage] = useState<"intro" | "setup" | "verify" | "success">("intro");
  const [setupData, setSetupData] = useState<Setup2FAResponse | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const startSetup = async () => {
    setLoading(true);
    try {
      const res = await apiFetch("/v1/auth/2fa/setup", {
        method: "POST",
        body: JSON.stringify({ id: user.id }),
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setSetupData(data);
      setPage("setup");
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const verifyCode = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiFetch("/v1/auth/2fa/verify", {
        method: "POST",
        body: JSON.stringify({ id: user.id, code }),
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      if (data.success) {
        setPage("success");
        onSuccess();
      } else {
        setError("Invalid code. Please try again.");
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setPage("intro");
    setSetupData(null);
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
          <>
            <Text size="sm">
              Two-factor authentication (2FA) adds an extra layer of security to your account.
              In addition to your password, you'll need to enter a code from an authenticator app.
            </Text>
            <Button onClick={startSetup} loading={loading} fullWidth>
              Enable 2FA
            </Button>
          </>
        )}

        {step === "setup" && setupData && (
          <>
            <Text size="sm" fw={500}>1. Scan this QR Code</Text>
            <Group justify="center">
              <Image src={setupData.qr_code_url} w={200} h={200} alt="2FA QR Code" />
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
                {setupData.recovery_codes.map((c) => (
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
              placeholder="000000"
              value={code}
              onChange={(e) => setCode(e.currentTarget.value)}
              error={error}
              autoFocus
            />
            <Button onClick={verifyCode} loading={loading} fullWidth>
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
