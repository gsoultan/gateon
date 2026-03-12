import {
  AppShell,
  Burger,
  Group,
  ScrollArea,
  NavLink,
  Title,
  Badge,
  Text,
  ActionIcon,
  Tooltip,
  Stack,
  Divider,
  Box,
  UnstyledButton,
  useMantineColorScheme,
  useMantineTheme,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { Link, Outlet, useLocation } from "@tanstack/react-router";
import { useGateonStatus } from "../hooks/useGateon";
import { useThemeStore } from "../store/useThemeStore";
import { useAuthStore } from "../store/useAuthStore";
import {
  IconDashboard,
  IconRoute,
  IconServer,
  IconTerminal2,
  IconSettings,
  IconActivity,
  IconCertificate,
  IconShieldLock,
  IconLockAccess,
  IconSettingsAutomation,
  IconRefresh,
  IconUsers,
  IconAccessPoint,
  IconPower,
  IconChevronLeft,
  IconChevronRight,
  IconSun,
  IconMoon,
} from "@tabler/icons-react";

export function Shell() {
  const [mobileOpened, { toggle: toggleMobile }] = useDisclosure();
  const [desktopOpened, { toggle: toggleDesktop }] = useDisclosure(true);
  const location = useLocation();
  const { data: status, refetch, isFetching } = useGateonStatus();
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  const setGlobalColorScheme = useThemeStore((state) => state.setColorScheme);
  const logout = useAuthStore((state) => state.logout);
  const user = useAuthStore((state) => state.user);
  const theme = useMantineTheme();

  const toggleColorScheme = () => {
    const nextScheme = colorScheme === "dark" ? "light" : "dark";
    setColorScheme(nextScheme);
    setGlobalColorScheme(nextScheme);
  };

  const coreLinks = [
    { label: "Dashboard", to: "/", icon: IconDashboard },
    { label: "Routes", to: "/routes", icon: IconRoute },
    { label: "Services", to: "/services", icon: IconServer },
    { label: "Path Metrics", to: "/path-metrics", icon: IconActivity },
    { label: "EntryPoints", to: "/entrypoints", icon: IconAccessPoint },
  ];

  const securityLinks = [
    { label: "Certificates", to: "/certificates", icon: IconCertificate },
    {
      label: "Client Authorities",
      to: "/client-authorities",
      icon: IconShieldLock,
    },
    { label: "TLS Options", to: "/tls-options", icon: IconLockAccess },
    { label: "Middlewares", to: "/middlewares", icon: IconSettingsAutomation },
  ];

  const systemLinks = [
    { label: "Logs", to: "/logs", icon: IconTerminal2 },
    ...(user?.role === "admin"
      ? [{ label: "Users", to: "/users", icon: IconUsers }]
      : []),
    { label: "Settings", to: "/settings", icon: IconSettings },
  ];

  return (
    <AppShell
      header={{ height: 64 }}
      navbar={{
        width: desktopOpened ? 260 : 80,
        breakpoint: "sm",
        collapsed: { mobile: !mobileOpened },
      }}
      padding="md"
      styles={{
        main: {
          backgroundColor:
            colorScheme === "dark"
              ? "var(--mantine-color-dark-8)"
              : "var(--mantine-color-gray-0)",
          transition: "padding-left 300ms ease, background-color 200ms ease",
        },
        navbar: {
          transition: "width 300ms ease, border-color 200ms ease",
          overflow: "hidden",
          borderRight: `1px solid ${colorScheme === "dark" ? "var(--mantine-color-dark-4)" : "var(--mantine-color-gray-2)"}`,
        },
        header: {
          backgroundColor:
            colorScheme === "dark"
              ? "var(--mantine-color-dark-7)"
              : "var(--mantine-color-white)",
          borderBottom: `1px solid ${colorScheme === "dark" ? "var(--mantine-color-dark-4)" : "var(--mantine-color-gray-2)"}`,
        },
      }}
    >
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between">
          <Group>
            <Burger
              opened={mobileOpened}
              onClick={toggleMobile}
              hiddenFrom="sm"
              size="sm"
            />
            <ActionIcon
              onClick={toggleDesktop}
              visibleFrom="sm"
              variant="subtle"
              color="gray"
            >
              {desktopOpened ? (
                <IconChevronLeft size={18} />
              ) : (
                <IconChevronRight size={18} />
              )}
            </ActionIcon>
            <Group gap="xs">
              <IconActivity
                size={24}
                color="var(--mantine-color-indigo-filled)"
              />
              <Title order={3} fw={800} style={{ letterSpacing: -1 }}>
                GATEON
              </Title>
            </Group>
          </Group>

          <Group gap="lg" visibleFrom="md">
            <Group gap="md">
              <Stack gap={0} align="flex-end">
                <Text size="xs" fw={700} c="dimmed" lh={1}>
                  STATUS
                </Text>
                <Badge
                  size="sm"
                  color={status?.status === "running" ? "green" : "red"}
                  variant="dot"
                  styles={{ root: { border: 0 } }}
                >
                  {status?.status?.toUpperCase() || "OFFLINE"}
                </Badge>
              </Stack>

              <Stack gap={0} align="flex-end">
                <Text size="xs" fw={700} c="dimmed" lh={1}>
                  VERSION
                </Text>
                <Text size="sm" fw={600}>
                  {status?.version || "N/A"}
                </Text>
              </Stack>
            </Group>

            <Group gap="xs">
              <Tooltip
                label={
                  colorScheme === "dark" ? "Switch to Light" : "Switch to Dark"
                }
              >
                <ActionIcon
                  variant="default"
                  onClick={toggleColorScheme}
                  size="lg"
                  radius="md"
                >
                  {colorScheme === "dark" ? (
                    <IconSun size={18} />
                  ) : (
                    <IconMoon size={18} />
                  )}
                </ActionIcon>
              </Tooltip>
              <Tooltip label="Refresh Status">
                <ActionIcon
                  variant="subtle"
                  color="gray"
                  onClick={() => refetch()}
                  loading={isFetching}
                >
                  <IconRefresh size={18} />
                </ActionIcon>
              </Tooltip>
              <Tooltip label="Logout">
                <ActionIcon
                  variant="light"
                  color="red"
                  onClick={() => logout()}
                >
                  <IconPower size={18} />
                </ActionIcon>
              </Tooltip>
            </Group>
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p="md">
        <AppShell.Section grow component={ScrollArea}>
          <Stack gap="sm">
            {desktopOpened && (
              <Text
                size="xs"
                fw={800}
                c="dimmed"
                px="xs"
                style={{ textTransform: "uppercase", letterSpacing: 1 }}
              >
                CORE
              </Text>
            )}
            <Stack gap="xs">
              {coreLinks.map((l) => (
                <Tooltip
                  key={l.to}
                  label={l.label}
                  position="right"
                  disabled={desktopOpened}
                  offset={15}
                >
                  <NavLink
                    label={desktopOpened ? l.label : null}
                    leftSection={<l.icon size={22} stroke={1.5} />}
                    component={Link as any}
                    to={l.to}
                    active={location.pathname === l.to}
                    variant="filled"
                    styles={{
                      root: {
                        borderRadius: "var(--mantine-radius-md)",
                        fontWeight: 500,
                        height: 48,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: desktopOpened ? "flex-start" : "center",
                        padding: desktopOpened ? "0 12px" : 0,
                      },
                      section: {
                        marginRight: desktopOpened ? 12 : 0,
                      },
                    }}
                  />
                </Tooltip>
              ))}
            </Stack>

            <Divider my="xs" variant="transparent" />

            {desktopOpened && (
              <Text
                size="xs"
                fw={800}
                c="dimmed"
                px="xs"
                style={{ textTransform: "uppercase", letterSpacing: 1 }}
              >
                SECURITY
              </Text>
            )}
            <Stack gap="xs">
              {securityLinks.map((l) => (
                <Tooltip
                  key={l.to}
                  label={l.label}
                  position="right"
                  disabled={desktopOpened}
                  offset={15}
                >
                  <NavLink
                    label={desktopOpened ? l.label : null}
                    leftSection={<l.icon size={22} stroke={1.5} />}
                    component={Link as any}
                    to={l.to}
                    active={location.pathname === l.to}
                    variant="filled"
                    styles={{
                      root: {
                        borderRadius: "var(--mantine-radius-md)",
                        fontWeight: 500,
                        height: 48,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: desktopOpened ? "flex-start" : "center",
                        padding: desktopOpened ? "0 12px" : 0,
                      },
                      section: {
                        marginRight: desktopOpened ? 12 : 0,
                      },
                    }}
                  />
                </Tooltip>
              ))}
            </Stack>

            <Divider my="xs" variant="transparent" />

            {desktopOpened && (
              <Text
                size="xs"
                fw={800}
                c="dimmed"
                px="xs"
                style={{ textTransform: "uppercase", letterSpacing: 1 }}
              >
                SYSTEM
              </Text>
            )}
            <Stack gap="xs">
              {systemLinks.map((l) => (
                <Tooltip
                  key={l.to}
                  label={l.label}
                  position="right"
                  disabled={desktopOpened}
                  offset={15}
                >
                  <NavLink
                    label={desktopOpened ? l.label : null}
                    leftSection={<l.icon size={22} stroke={1.5} />}
                    component={Link as any}
                    to={l.to}
                    active={location.pathname === l.to}
                    variant="filled"
                    styles={{
                      root: {
                        borderRadius: "var(--mantine-radius-md)",
                        fontWeight: 500,
                        height: 48,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: desktopOpened ? "flex-start" : "center",
                        padding: desktopOpened ? "0 12px" : 0,
                      },
                      section: {
                        marginRight: desktopOpened ? 12 : 0,
                      },
                    }}
                  />
                </Tooltip>
              ))}
            </Stack>
          </Stack>
        </AppShell.Section>

        <AppShell.Section>
          <Divider my="sm" />
          <Box
            px={desktopOpened ? "xs" : 0}
            pb="xs"
            style={{ textAlign: "center" }}
          >
            {desktopOpened ? (
              <Group justify="space-between">
                <Text size="xs" c="dimmed">
                  © 2026 Gateon
                </Text>
                <Badge size="xs" variant="outline">
                  OSS
                </Badge>
              </Group>
            ) : (
              <Badge size="xs" variant="outline">
                OSS
              </Badge>
            )}
          </Box>
        </AppShell.Section>
      </AppShell.Navbar>

      <AppShell.Main>
        <Box style={{ maxWidth: 1400, margin: "0 auto", paddingBottom: 40 }}>
          <Outlet />
        </Box>
      </AppShell.Main>
    </AppShell>
  );
}
