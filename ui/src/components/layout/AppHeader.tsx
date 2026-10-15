// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import {
  ActionIcon,
  Avatar,
  Badge,
  Box,
  Burger,
  Group,
  Menu,
  Text,
  Tooltip,
  UnstyledButton,
  useMantineColorScheme,
} from "@mantine/core";
import { Link } from "@tanstack/react-router";
import {
  IconCheck,
  IconDeviceDesktop,
  IconLayoutSidebarLeftCollapse,
  IconLayoutSidebarLeftExpand,
  IconLogout,
  IconMoon,
  IconRefresh,
  IconSun,
  IconUser,
} from "@tabler/icons-react";
import { CommandSearchButton } from "../CommandPalette/CommandSearchButton";
import { ConnectionStatus } from "../ConnectionStatus";
import { GlobalHealthBar } from "../GlobalHealthBar";
import { SIGN_OUT_SCOPE } from "../signOut";
import classes from "./layout.module.css";

type Scheme = "light" | "dark" | "auto";

const SCHEMES: { value: Scheme; label: string; icon: typeof IconSun }[] = [
  { value: "light", label: "Light", icon: IconSun },
  { value: "dark", label: "Dark", icon: IconMoon },
  { value: "auto", label: "Follow system", icon: IconDeviceDesktop },
];

const ROLE_COLOR: Record<string, string> = { admin: "red", operator: "blue" };

interface AppHeaderProps {
  mobileOpened: boolean;
  onToggleMobile: () => void;
  sidebarExpanded: boolean;
  onToggleSidebar: () => void;
  username: string | undefined;
  role: string | undefined;
  version: string | undefined;
  refreshing: boolean;
  onRefresh: () => void;
  onSignOut: () => void;
}

function ThemeMenu() {
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  const Current = SCHEMES.find((s) => s.value === colorScheme)?.icon ?? IconDeviceDesktop;
  return (
    <Menu width={200} position="bottom-end">
      <Menu.Target>
        <Tooltip label="Theme">
          <ActionIcon variant="subtle" color="gray" size="lg" aria-label="Change color scheme">
            <Current size={19} stroke={1.6} />
          </ActionIcon>
        </Tooltip>
      </Menu.Target>
      <Menu.Dropdown>
        <Menu.Label>Appearance</Menu.Label>
        {SCHEMES.map(({ value, label, icon: Icon }) => (
          <Menu.Item
            key={value}
            leftSection={<Icon size={16} stroke={1.6} />}
            rightSection={colorScheme === value ? <IconCheck size={14} /> : null}
            onClick={() => setColorScheme(value)}
          >
            {label}
          </Menu.Item>
        ))}
      </Menu.Dropdown>
    </Menu>
  );
}

function AccountMenu({ username, role, version, onSignOut }: Pick<AppHeaderProps, "username" | "role" | "version" | "onSignOut">) {
  return (
    <Menu width={240} position="bottom-end">
      <Menu.Target>
        <UnstyledButton aria-label="Account menu">
          <Avatar color="brand" radius="xl" size={32}>
            {username?.charAt(0)?.toUpperCase() || <IconUser size={18} />}
          </Avatar>
        </UnstyledButton>
      </Menu.Target>
      <Menu.Dropdown>
        <Box px="sm" py={8}>
          <Group justify="space-between" wrap="nowrap" gap="xs">
            <Text size="sm" fw={600} truncate>
              {username || "Account"}
            </Text>
            {role && (
              <Badge size="sm" color={ROLE_COLOR[role] ?? "gray"}>
                {role}
              </Badge>
            )}
          </Group>
          {version && (
            <Text size="xs" c="dimmed" mt={2}>
              Gateon {version}
            </Text>
          )}
        </Box>
        <Menu.Divider />
        <Menu.Item leftSection={<IconUser size={16} stroke={1.6} />} component={Link} to="/profile">
          Profile
        </Menu.Item>
        <Menu.Item color="red" leftSection={<IconLogout size={16} stroke={1.6} />} onClick={onSignOut}>
          Sign out
          <Text size="xs" c="dimmed">
            {SIGN_OUT_SCOPE}
          </Text>
        </Menu.Item>
      </Menu.Dropdown>
    </Menu>
  );
}

export function AppHeader(props: AppHeaderProps) {
  const { mobileOpened, onToggleMobile, sidebarExpanded, onToggleSidebar, refreshing, onRefresh } = props;
  return (
    <Group h="100%" px="md" justify="space-between" wrap="nowrap" gap="md">
      <Group gap="sm" wrap="nowrap" style={{ flexShrink: 0 }}>
        <Burger opened={mobileOpened} onClick={onToggleMobile} hiddenFrom="sm" size="sm" aria-label="Toggle navigation menu" />
        <Tooltip label={sidebarExpanded ? "Collapse sidebar" : "Expand sidebar"}>
          <ActionIcon
            onClick={onToggleSidebar}
            visibleFrom="sm"
            variant="subtle"
            color="gray"
            size="lg"
            aria-label={sidebarExpanded ? "Collapse sidebar" : "Expand sidebar"}
          >
            {sidebarExpanded ? <IconLayoutSidebarLeftCollapse size={19} stroke={1.6} /> : <IconLayoutSidebarLeftExpand size={19} stroke={1.6} />}
          </ActionIcon>
        </Tooltip>
        <Link to="/" className={classes.brand} aria-label="Gateon dashboard">
          <img src="/gateon-logo.svg" alt="" width={26} height={26} style={{ display: "block" }} />
          <span className={classes.brandName}>GATEON</span>
        </Link>
      </Group>

      <Group gap="sm" wrap="nowrap" justify="flex-end" style={{ flex: 1, minWidth: 0 }}>
        <Box visibleFrom="sm">
          <CommandSearchButton />
        </Box>
        <Box visibleFrom="lg">
          <GlobalHealthBar />
        </Box>
        <Box visibleFrom="md">
          <ConnectionStatus />
        </Box>
        <Group gap={4} wrap="nowrap">
          <Tooltip label="Refresh status">
            <ActionIcon variant="subtle" color="gray" size="lg" onClick={onRefresh} loading={refreshing} aria-label="Refresh status">
              <IconRefresh size={19} stroke={1.6} />
            </ActionIcon>
          </Tooltip>
          <ThemeMenu />
        </Group>
        <AccountMenu {...props} />
      </Group>
    </Group>
  );
}
