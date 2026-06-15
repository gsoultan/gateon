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
  PasswordInput,
  Stack,
  Text,
  ThemeIcon,
  Title,
  Tooltip,
} from "@mantine/core";
import { useForm } from "@mantine/form";
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
import { apiFetch, getApiErrorMessage } from "../hooks/useGateon";
import { useAuthStore } from "../store/useAuthStore";
import { queryClient } from "../queryClient";
import { TwoFactorModal } from "../components/TwoFactorModal";

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
  const [pwLoading, setPwLoading] = useState(false);
  const [signingOut, setSigningOut] = useState(false);

  const passwordForm = useForm({
    initialValues: {
      password: "",
      confirmPassword: "",
    },
    validate: {
      password: (value) =>
        value.length < 6 ? "Password must be at least 6 characters" : null,
      confirmPassword: (value, values) =>
        value !== values.password ? "Passwords do not match" : null,
    },
  });

  const handlePasswordSubmit = async (values: typeof passwordForm.values) => {
    if (!user) return;
    setPwLoading(true);
    try {
      const res = await apiFetch("/v1/users/password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: user.id, password: values.password }),
      });
      if (!res.ok) throw new Error(await res.text());
      notifications.show({
        title: "Password updated",
        message: "Your password has been changed successfully.",
        color: "green",
        icon: <IconCheck size={16} />,
      });
      passwordForm.reset();
    } catch (err) {
      notifications.show({
        title: "Failed to update password",
        message: getApiErrorMessage(err),
        color: "red",
      });
    } finally {
      setPwLoading(false);
    }
  };

  const handle2FASuccess = () => {
    if (user) {
      setAuth(token ?? "__cookie__", { ...user, two_factor_enabled: true });
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
  const twoFactorEnabled = !!user?.two_factor_enabled;

  return (
    <Stack gap="lg">
      <Group gap="sm">
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
          <Group gap="lg" wrap="nowrap">
            <Avatar color="blue" radius="xl" size={72}>
              {initial || <IconUser size={36} />}
            </Avatar>
            <Stack gap={4}>
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

      <Grid gutter="lg">
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
            <form onSubmit={passwordForm.onSubmit(handlePasswordSubmit)}>
              <Stack gap="sm">
                <PasswordInput
                  label="New password"
                  placeholder="Enter new password"
                  autoComplete="new-password"
                  {...passwordForm.getInputProps("password")}
                />
                <PasswordInput
                  label="Confirm password"
                  placeholder="Re-enter new password"
                  autoComplete="new-password"
                  {...passwordForm.getInputProps("confirmPassword")}
                />
                <Group justify="flex-end" mt="xs">
                  <Button type="submit" loading={pwLoading}>
                    Update password
                  </Button>
                </Group>
              </Stack>
            </form>
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
