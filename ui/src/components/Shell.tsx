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
  useMantineColorScheme,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { Link, Outlet, useLocation, useNavigate } from "@tanstack/react-router";
import { useGateonStatus } from "../hooks/useGateon";
import { usePermissions } from "../hooks/usePermissions";
import { GlobalHealthBar } from "./GlobalHealthBar";
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
  IconDeviceDesktop,
  IconCircuitSwitchClosed,
  IconBook2,
  IconNetwork,
  IconTimeline,
  IconBrain,
  IconChartBar,
  IconStethoscope,
} from "@tabler/icons-react";

export function Shell() {
  const [mobileOpened, { toggle: toggleMobile }] = useDisclosure();
  const [desktopOpened, { toggle: toggleDesktop }] = useDisclosure(true);
  const location = useLocation();
  const { data: status, refetch, isFetching } = useGateonStatus();
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  const logout = useAuthStore((state) => state.logout);
  const navigate = useNavigate();
  const user = useAuthStore((state) => state.user);
  const { isViewer } = usePermissions();

  const cycleScheme = (next: "light" | "dark" | "auto") => {
    setColorScheme(next);
  };

  const coreLinks = [
    { label: "Dashboard", to: "/", icon: IconDashboard },
    { label: "AI Insights", to: "/ai-insights", icon: IconBrain },
    { label: "Topology", to: "/topology", icon: IconNetwork },
    { label: "Traces", to: "/traces", icon: IconTimeline },
    { label: "Routes", to: "/routes", icon: IconRoute },
    { label: "Services", to: "/services", icon: IconServer },
    { label: "Metrics", to: "/metrics", icon: IconChartBar },
    { label: "Path Metrics", to: "/path-metrics", icon: IconActivity },
    { label: "Circuit Breaker", to: "/circuit-breaker", icon: IconCircuitSwitchClosed },
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
    { label: "Docs", to: "/docs", icon: IconBook2 },
    { label: "Diagnostics", to: "/diagnostics", icon: IconStethoscope },
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
          overflow: "hidden",
          boxShadow: colorScheme === "dark" ? "0 1px 0 rgba(255,255,255,0.03)" : "0 1px 3px rgba(0,0,0,0.04)",
        },
      }}
    >
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
            />
            <ActionIcon
              onClick={toggleDesktop}
              visibleFrom="sm"
              variant="subtle"
              color="gray"
              size="lg"
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
            <Group visibleFrom="lg" style={{ flexShrink: 0 }}>
              <GlobalHealthBar />
            </Group>
            <Group gap={{ base: "xs", md: "sm" }} style={{ flexShrink: 0 }}>
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
              <Menu shadow="md" width={160} position="bottom-end">
                <Menu.Target>
                  <Tooltip label="Theme (Light / Dark / System)">
                    <ActionIcon variant="default" size="md" radius="md">
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
                <Menu.Dropdown>
                  <Menu.Item
                    leftSection={<IconSun size={16} />}
                    onClick={() => cycleScheme("light")}
                  >
                    Light
                  </Menu.Item>
                  <Menu.Item
                    leftSection={<IconMoon size={16} />}
                    onClick={() => cycleScheme("dark")}
                  >
                    Dark
                  </Menu.Item>
                  <Menu.Item
                    leftSection={<IconDeviceDesktop size={16} />}
                    onClick={() => cycleScheme("auto")}
                  >
                    System
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
                >
                  <IconRefresh size={18} />
                </ActionIcon>
              </Tooltip>
              <Tooltip label="Logout">
                <ActionIcon
                  variant="light"
                  color="red"
                  size="md"
                  onClick={() => { logout(); void navigate({ to: "/login" }); }}
                >
                  <IconPower size={18} />
                </ActionIcon>
              </Tooltip>
            </Group>
          </Flex>
        </Flex>
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
  );
}
