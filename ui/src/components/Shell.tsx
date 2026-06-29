import { useMemo, useCallback } from "react";
import {
  Alert,
  AppShell,
  Burger,
  Flex,
  Group,
  Menu,
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
  Avatar,
  UnstyledButton,
  useMantineColorScheme,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { Link, Outlet, useLocation, useNavigate } from "@tanstack/react-router";
import { apiFetch, useGateonStatus } from "../hooks/useGateon";
import { queryClient } from "../queryClient";
import { usePermissions } from "../hooks/usePermissions";
import { GlobalHealthBar } from "./GlobalHealthBar";
import { useAuthStore } from "../store/useAuthStore";
import { usePreferencesStore } from "../store/usePreferencesStore";
import { CommandPaletteProvider } from "./CommandPalette";
import { CommandSearchButton } from "./CommandPalette/CommandSearchButton";
import { ConnectionStatus } from "./ConnectionStatus";
import {
  IconDashboard,
  IconRoute,
  IconServer,
  IconTerminal2,
  IconSettings,
  IconActivity,
  IconCertificate,
  IconShieldLock,
  IconShieldCheck,
  IconLockAccess,
  IconSettingsAutomation,
  IconRefresh,
  IconUsers,
  IconAccessPoint,
  IconChevronLeft,
  IconChevronRight,
  IconSun,
  IconMoon,
  IconDeviceDesktop,
  IconCircuitSwitchClosed,
  IconBook2,
  IconNetwork,
  IconTimeline,
  IconChartBar,
  IconStethoscope,
  IconUser,
  IconLogout,
} from "@tabler/icons-react";

const CORE_LINKS = [
  { label: "Dashboard", to: "/", icon: IconDashboard },
  { label: "Topology", to: "/topology", icon: IconNetwork },
  { label: "Traces", to: "/traces", icon: IconTimeline },
  { label: "Routes", to: "/routes", icon: IconRoute },
  { label: "Services", to: "/services", icon: IconServer },
  { label: "Metrics", to: "/metrics", icon: IconChartBar },
  { label: "Path Metrics", to: "/path-metrics", icon: IconActivity },
  { label: "Circuit Breaker", to: "/circuit-breaker", icon: IconCircuitSwitchClosed },
  { label: "EntryPoints", to: "/entrypoints", icon: IconAccessPoint },
];

export function Shell() {
  const [mobileOpened, { toggle: toggleMobile }] = useDisclosure();
  const sidebarCollapsed = usePreferencesStore((state) => state.sidebarCollapsed);
  const toggleDesktop = usePreferencesStore((state) => state.toggleSidebar);
  const desktopOpened = !sidebarCollapsed;
  const location = useLocation();
  const { data: status, refetch, isFetching } = useGateonStatus();
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  const logout = useAuthStore((state) => state.logout);
  const navigate = useNavigate();
  const user = useAuthStore((state) => state.user);
  const { isViewer } = usePermissions();

  const cycleScheme = useCallback((next: "light" | "dark" | "auto") => {
    setColorScheme(next);
  }, [setColorScheme]);

  const securityLinks = useMemo(() => [
    { label: "Security Hub", to: "/security-center", icon: IconShieldCheck },
    // Audit Logs are an admin/operator surface (global resource); a read-only
    // Viewer would only hit a 403 here, so hide the link for them.
    ...(isViewer
      ? []
      : [{ label: "Audit Logs", to: "/audit-logs", icon: IconTimeline }]),
    { label: "Certificates", to: "/certificates", icon: IconCertificate },
    {
      label: "Client Authorities",
      to: "/client-authorities",
      icon: IconShieldLock,
    },
    { label: "TLS Options", to: "/tls-options", icon: IconLockAccess },
    { label: "Middlewares", to: "/middlewares", icon: IconSettingsAutomation },
  ], [isViewer]);

  const systemLinks = useMemo(() => [
    { label: "Docs", to: "/docs", icon: IconBook2 },
    { label: "Diagnostics", to: "/diagnostics", icon: IconStethoscope },
    { label: "Logs", to: "/logs", icon: IconTerminal2 },
    ...(user?.role === "admin"
      ? [{ label: "Users", to: "/users", icon: IconUsers }]
      : []),
    // The global Settings editor is the global-config resource (admin/operator).
    ...(isViewer
      ? []
      : [{ label: "Settings", to: "/settings", icon: IconSettings }]),
  ], [isViewer, user?.role]);

  return (
    <CommandPaletteProvider>
    <AppShell
      header={{ height: 60 }}
      navbar={{
        width: desktopOpened ? 240 : 80,
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
          backgroundColor: colorScheme === "dark" ? "var(--mantine-color-dark-7)" : "var(--mantine-color-white)",
          borderRight: `1px solid ${colorScheme === "dark" ? "var(--mantine-color-dark-5)" : "var(--mantine-color-gray-2)"}`,
        },
        header: {
          backgroundColor:
            colorScheme === "dark"
              ? "var(--mantine-color-dark-7)"
              : "var(--mantine-color-white)",
          borderBottom: `1px solid ${colorScheme === "dark" ? "var(--mantine-color-dark-5)" : "var(--mantine-color-gray-2)"}`,
          overflow: "hidden",
          boxShadow: "var(--mantine-shadow-xs)",
        },
      }}
    >
      <a href="#main-content" className="skip-to-content">
        Skip to main content
      </a>
      <AppShell.Header>
        <Flex
          h="100%"
          px="md"
          align="center"
          justify="space-between"
          gap="md"
          wrap="nowrap"
          style={{ minHeight: 64, minWidth: 0 }}
        >
          <Group gap="xs" style={{ flexShrink: 0 }}>
            <Burger
              opened={mobileOpened}
              onClick={toggleMobile}
              hiddenFrom="sm"
              size="sm"
              aria-label="Toggle navigation menu"
            />
            <ActionIcon
              onClick={toggleDesktop}
              visibleFrom="sm"
              variant="subtle"
              color="gray"
              size="lg"
              aria-label={desktopOpened ? "Collapse sidebar" : "Expand sidebar"}
            >
              {desktopOpened ? (
                <IconChevronLeft size={18} />
              ) : (
                <IconChevronRight size={18} />
              )}
            </ActionIcon>
            <Group gap="xs">
              <Box
                component="img"
                src="/gateon-logo.svg"
                alt="Gateon logo"
                w={28}
                h={28}
                style={{ display: "block", flexShrink: 0 }}
              />
              <Title order={4} fw={800} style={{ letterSpacing: -0.5 }}>
                GATEON
              </Title>
            </Group>
          </Group>

          <Flex
            align="center"
            gap={{ base: "xs", md: "sm", lg: "lg" }}
            visibleFrom="sm"
            style={{ flex: 1, minWidth: 0, justifyContent: "flex-end" }}
          >
            <CommandSearchButton />
            <Group visibleFrom="lg" style={{ flexShrink: 0 }}>
              <GlobalHealthBar />
            </Group>
            <Group gap="xs" style={{ flexShrink: 0 }}>
              <ConnectionStatus />

              {user?.role && (
                <Stack gap={0} align="flex-end" visibleFrom="md">
                  <Text size="xs" fw={700} c="dimmed" lh={1}>
                    ROLE
                  </Text>
                  <Badge
                    size="sm"
                    variant="light"
                    color={user.role === "admin" ? "red" : user.role === "operator" ? "blue" : "gray"}
                  >
                    {user.role}
                  </Badge>
                </Stack>
              )}
              <Stack gap={0} align="flex-end" visibleFrom="lg">
                <Text size="xs" fw={700} c="dimmed" lh={1}>
                  VERSION
                </Text>
                <Text size="sm" fw={600}>
                  {status?.version || "N/A"}
                </Text>
              </Stack>
            </Group>

            <Group gap="xs" style={{ flexShrink: 0 }}>
      <Menu shadow="md" width={220} position="bottom-end">
        <Menu.Target>
          <Tooltip label="Theme (Light / Dark / System)">
            <ActionIcon variant="default" size="md" radius="md" aria-label="Change color scheme">
              {colorScheme === "auto" ? (
                <IconDeviceDesktop size={18} />
              ) : colorScheme === "dark" ? (
                <IconMoon size={18} />
              ) : (
                <IconSun size={18} />
              )}
            </ActionIcon>
          </Tooltip>
        </Menu.Target>
        <Menu.Dropdown p={4}>
          <Menu.Label>Appearance</Menu.Label>
          <Menu.Item
            leftSection={<IconSun size={16} stroke={1.5} />}
            onClick={() => cycleScheme("light")}
          >
            Light Mode {colorScheme === "light" && "✓"}
          </Menu.Item>
          <Menu.Item
            leftSection={<IconMoon size={16} stroke={1.5} />}
            onClick={() => cycleScheme("dark")}
          >
            Dark Mode {colorScheme === "dark" && "✓"}
          </Menu.Item>
          <Menu.Item
            leftSection={<IconDeviceDesktop size={16} stroke={1.5} />}
            onClick={() => cycleScheme("auto")}
          >
            Follow System {colorScheme === "auto" && "✓"}
          </Menu.Item>
        </Menu.Dropdown>
      </Menu>

      <Menu shadow="md" width={220} position="bottom-end">
        <Menu.Target>
          <Tooltip label="Profile">
            <UnstyledButton aria-label="Profile menu">
              <Avatar color="blue" radius="xl" size={34}>
                {user?.username?.charAt(0)?.toUpperCase() || (
                  <IconUser size={18} />
                )}
              </Avatar>
            </UnstyledButton>
          </Tooltip>
        </Menu.Target>
        <Menu.Dropdown p={4}>
          <Menu.Label>
            {user?.username || "Account"}
            {user?.role ? ` (${user.role})` : ""}
          </Menu.Label>
          <Menu.Item
            leftSection={<IconUser size={16} stroke={1.5} />}
            component={Link as any}
            to="/profile"
          >
            Profile
          </Menu.Item>
          <Menu.Divider />
          <Menu.Item
            color="red"
            leftSection={<IconLogout size={16} stroke={1.5} />}
            onClick={() => {
              void (async () => {
                try {
                  await apiFetch("/v1/logout", { method: "POST" });
                } catch {
                  // Ignore network errors; clear local session regardless.
                } finally {
                  // Drop cached, potentially sensitive data from this session.
                  queryClient.clear();
                  logout();
                  void navigate({ to: "/login" });
                }
              })();
            }}
          >
            Sign out
          </Menu.Item>
        </Menu.Dropdown>
      </Menu>
              <Tooltip label="Refresh Status">
                <ActionIcon
                  variant="subtle"
                  color="gray"
                  size="md"
                  onClick={() => refetch()}
                  loading={isFetching}
                  aria-label="Refresh status"
                >
                  <IconRefresh size={18} />
                </ActionIcon>
              </Tooltip>
            </Group>
          </Flex>
        </Flex>
      </AppShell.Header>

      <AppShell.Navbar p="md">
        <AppShell.Section grow component={ScrollArea}>
          <Stack gap={2}>
            {desktopOpened && (
              <Text
                size="xs"
                fw={700}
                c="dimmed"
                px="md"
                mt="md"
                mb={4}
                style={{ textTransform: "uppercase", letterSpacing: 0.5 }}
              >
                Core
              </Text>
            )}
            <Stack gap={2}>
              {CORE_LINKS.map((l) => (
                <Tooltip
                  key={l.to}
                  label={l.label}
                  position="right"
                  disabled={desktopOpened}
                  offset={15}
                >
                  <NavLink
                    label={desktopOpened ? l.label : null}
                    leftSection={<l.icon size={20} stroke={1.5} />}
                    component={Link as any}
                    to={l.to}
                    active={location.pathname === l.to}
                    variant="light"
                    styles={{
                      root: {
                        borderRadius: "var(--mantine-radius-sm)",
                        fontWeight: 600,
                        height: 40,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: desktopOpened ? "flex-start" : "center",
                        padding: desktopOpened ? "0 12px" : 0,
                        margin: "0 8px",
                      },
                      section: {
                        marginRight: desktopOpened ? 12 : 0,
                      },
                    }}
                  />
                </Tooltip>
              ))}
            </Stack>

            {desktopOpened && (
              <Text
                size="xs"
                fw={700}
                c="dimmed"
                px="md"
                mt="lg"
                mb={4}
                style={{ textTransform: "uppercase", letterSpacing: 0.5 }}
              >
                Security
              </Text>
            )}
            <Stack gap={2}>
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
                    leftSection={<l.icon size={20} stroke={1.5} />}
                    component={Link as any}
                    to={l.to}
                    active={location.pathname === l.to}
                    variant="light"
                    styles={{
                      root: {
                        borderRadius: "var(--mantine-radius-sm)",
                        fontWeight: 600,
                        height: 40,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: desktopOpened ? "flex-start" : "center",
                        padding: desktopOpened ? "0 12px" : 0,
                        margin: "0 8px",
                      },
                      section: {
                        marginRight: desktopOpened ? 12 : 0,
                      },
                    }}
                  />
                </Tooltip>
              ))}
            </Stack>

            {desktopOpened && (
              <Text
                size="xs"
                fw={700}
                c="dimmed"
                px="md"
                mt="lg"
                mb={4}
                style={{ textTransform: "uppercase", letterSpacing: 0.5 }}
              >
                System
              </Text>
            )}
            <Stack gap={2}>
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
                    leftSection={<l.icon size={20} stroke={1.5} />}
                    component={Link as any}
                    to={l.to}
                    active={location.pathname === l.to}
                    variant="light"
                    styles={{
                      root: {
                        borderRadius: "var(--mantine-radius-sm)",
                        fontWeight: 600,
                        height: 40,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: desktopOpened ? "flex-start" : "center",
                        padding: desktopOpened ? "0 12px" : 0,
                        margin: "0 8px",
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

      <AppShell.Main id="main-content">
        {isViewer && (
          <Alert
            mb="md"
            radius="md"
            color="blue"
            variant="light"
            title="View only"
            styles={{ root: { maxWidth: 1400, margin: "0 auto" } }}
          >
            You have read-only access. Create, edit, and delete actions are restricted.
          </Alert>
        )}
        <Box
          style={{
            maxWidth: 1400,
            margin: "0 auto",
            paddingBottom: 40,
            width: "100%",
            minWidth: 0,
          }}
        >
          <Outlet />
        </Box>
      </AppShell.Main>
    </AppShell>
    </CommandPaletteProvider>
  );
}
