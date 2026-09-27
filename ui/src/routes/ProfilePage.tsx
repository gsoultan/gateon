// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useState } from "react";
import {
  Avatar,
  Badge,
  Box,
  Button,
  Card,
  Divider,
  Grid,
  Group,
  Paper,
  Stack,
  Text,
  ThemeIcon,
  Title,
  Tooltip,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import { useNavigate } from "@tanstack/react-router";
import {
  IconCheck,
  IconKey,
  IconLogout,
  IconShieldCheck,
  IconShieldOff,
  IconUser,
  IconUserCircle,
} from "@tabler/icons-react";
import { apiFetch } from "../hooks/useGateon";
import { useAuthStore } from "../store/useAuthStore";
import { queryClient } from "../queryClient";
import { TwoFactorModal } from "../components/TwoFactorModal";
import { ChangePasswordForm } from "../components/ChangePasswordForm";

const ROLE_COLOR: Record<string, string> = {
  admin: "red",
  operator: "blue",
  viewer: "gray",
};

const ROLE_DESCRIPTION: Record<string, string> = {
  admin: "Full access: manage users, global config, and all resources.",
  operator: "Read & write access to routes, services, and configuration.",
  viewer: "Read-only access to dashboards and resources.",
};

export default function ProfilePage() {
  const user = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);
  const setAuth = useAuthStore((s) => s.setAuth);
  const token = useAuthStore((s) => s.token);
  const navigate = useNavigate();

  const [tfaOpened, { open: tfaOpen, close: tfaClose }] = useDisclosure(false);
  const [signingOut, setSigningOut] = useState(false);

  // Changing the password ends every session the account has, this one
  // included (the session is bound to the password), so say so and go to the
  // sign-in page instead of letting the next request fail.
  const handlePasswordChanged = () => {
    notifications.show({
      title: "Password changed",
      message: "Sign in again with your new password.",
      color: "green",
      icon: <IconCheck size={16} />,
    });
    queryClient.clear();
    logout();
    void navigate({ to: "/login" });
  };

  const handle2FASuccess = () => {
    if (user) {
      setAuth(token ?? "__cookie__", { ...user, twoFactorEnabled: true });
    }
    notifications.show({
      title: "Two-factor authentication enabled",
      message: "Your account is now protected with 2FA.",
      color: "green",
      icon: <IconShieldCheck size={16} />,
    });
  };

  const handleSignOut = async () => {
    setSigningOut(true);
    try {
      // Invalidate the server-side session (clears HttpOnly cookie).
      await apiFetch("/v1/logout", { method: "POST" });
    } catch {
      // Clear local session regardless of network errors.
    } finally {
      // Drop any cached, potentially sensitive data from this session.
      queryClient.clear();
      logout();
      void navigate({ to: "/login" });
    }
  };

  const username = user?.username ?? "Account";
  const role = user?.role ?? "viewer";
  const initial = user?.username?.charAt(0)?.toUpperCase();
  const twoFactorEnabled = !!user?.twoFactorEnabled;

  return (
    <Stack gap="lg">
      <Group gap="sm" wrap="wrap">
        <ThemeIcon size={36} radius="md" variant="light" color="blue">
          <IconUserCircle size={22} />
        </ThemeIcon>
        <Box>
          <Title order={2} fw={800} style={{ letterSpacing: -0.5 }}>
            Profile
          </Title>
          <Text size="sm" c="dimmed">
            Manage your account details and security settings.
          </Text>
        </Box>
      </Group>

      <Card withBorder radius="lg" shadow="sm" p="xl">
        <Group justify="space-between" wrap="wrap" gap="lg">
          <Group gap="lg" wrap="wrap">
            <Avatar color="blue" radius="xl" size={72}>
              {initial || <IconUser size={36} />}
            </Avatar>
            <Stack gap={4} style={{ flex: 1, minWidth: 200 }}>
              <Title order={3} fw={800}>
                {username}
              </Title>
              <Group gap="xs">
                <Badge color={ROLE_COLOR[role] ?? "gray"} variant="light" size="md">
                  {role}
                </Badge>
                <Badge
                  color={twoFactorEnabled ? "green" : "gray"}
                  variant="light"
                  size="md"
                  leftSection={
                    twoFactorEnabled ? (
                      <IconShieldCheck size={12} />
                    ) : (
                      <IconShieldOff size={12} />
                    )
                  }
                >
                  {twoFactorEnabled ? "2FA on" : "2FA off"}
                </Badge>
              </Group>
              <Text size="xs" c="dimmed" maw={420}>
                {ROLE_DESCRIPTION[role]}
              </Text>
            </Stack>
          </Group>
          <Button
            color="red"
            variant="light"
            leftSection={<IconLogout size={16} />}
            onClick={handleSignOut}
            loading={signingOut}
          >
            Sign out
          </Button>
        </Group>
      </Card>

      <Grid gap="lg">
        <Grid.Col span={{ base: 12, md: 6 }}>
          <Card withBorder radius="lg" shadow="sm" p="lg" h="100%">
            <Group gap="sm" mb="md">
              <ThemeIcon size={32} radius="md" variant="light" color="blue">
                <IconKey size={18} />
              </ThemeIcon>
              <Box>
                <Text fw={700}>Change password</Text>
                <Text size="xs" c="dimmed">
                  Use a strong, unique password.
                </Text>
              </Box>
            </Group>
            <Divider mb="md" />
            {user && (
              <ChangePasswordForm
                userId={user.id}
                own
                onChanged={handlePasswordChanged}
                submitLabel="Update password"
              />
            )}
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, md: 6 }}>
          <Card withBorder radius="lg" shadow="sm" p="lg" h="100%">
            <Group gap="sm" mb="md">
              <ThemeIcon
                size={32}
                radius="md"
                variant="light"
                color={twoFactorEnabled ? "green" : "blue"}
              >
                <IconShieldCheck size={18} />
              </ThemeIcon>
              <Box>
                <Text fw={700}>Two-factor authentication</Text>
                <Text size="xs" c="dimmed">
                  Add an extra layer of security at sign in.
                </Text>
              </Box>
            </Group>
            <Divider mb="md" />
            <Stack gap="md">
              <Paper withBorder radius="md" p="md">
                <Group justify="space-between">
                  <Group gap="sm">
                    <ThemeIcon
                      variant="light"
                      color={twoFactorEnabled ? "green" : "gray"}
                      radius="xl"
                    >
                      {twoFactorEnabled ? (
                        <IconShieldCheck size={16} />
                      ) : (
                        <IconShieldOff size={16} />
                      )}
                    </ThemeIcon>
                    <Text size="sm" fw={600}>
                      {twoFactorEnabled ? "Enabled" : "Not enabled"}
                    </Text>
                  </Group>
                  <Tooltip
                    label={
                      twoFactorEnabled
                        ? "2FA is already enabled for your account"
                        : "Set up an authenticator app"
                    }
                  >
                    <Button
                      variant={twoFactorEnabled ? "default" : "filled"}
                      disabled={twoFactorEnabled || !user}
                      onClick={tfaOpen}
                    >
                      {twoFactorEnabled ? "Active" : "Enable 2FA"}
                    </Button>
                  </Tooltip>
                </Group>
              </Paper>
              <Text size="xs" c="dimmed">
                When enabled, you'll need a code from your authenticator app in
                addition to your password each time you sign in.
              </Text>
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>

      {user && (
        <TwoFactorModal
          opened={tfaOpened}
          onClose={tfaClose}
          user={user}
          onSuccess={handle2FASuccess}
        />
      )}
    </Stack>
  );
}
