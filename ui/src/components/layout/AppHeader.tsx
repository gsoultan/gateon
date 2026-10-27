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
} from "@mantine/core";
import { Link } from "@tanstack/react-router";
import {
  IconBook2,
  IconLayoutSidebarLeftCollapse,
  IconLayoutSidebarLeftExpand,
  IconLogout,
  IconRefresh,
  IconUser,
} from "@tabler/icons-react";
import { CommandSearchButton } from "../CommandPalette/CommandSearchButton";
import { ConnectionStatus } from "../ConnectionStatus";
import { AttentionBadge } from "../Overview/AttentionBadge";
import { SIGN_OUT_SCOPE } from "../signOut";
import classes from "./layout.module.css";

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

/**
 * The status dot and, behind it, the one action that belongs to it. Refresh
 * used to be a button of its own in the header; it is a thing you do when the
 * status looks wrong, so it lives on the status.
 */
function StatusMenu({ refreshing, onRefresh }: Pick<AppHeaderProps, "refreshing" | "onRefresh">) {
  return (
    <Menu width={220} position="bottom-end">
      <Menu.Target>
        <UnstyledButton aria-label="Connection status and refresh">
          <ConnectionStatus />
        </UnstyledButton>
      </Menu.Target>
      <Menu.Dropdown>
        <Menu.Item leftSection={<IconRefresh size={16} stroke={1.6} />} onClick={onRefresh} disabled={refreshing}>
          {refreshing ? "Refreshing…" : "Refresh status"}
        </Menu.Item>
      </Menu.Dropdown>
    </Menu>
  );
}

/**
 * Logo, search, the attention badge, the status dot, docs and the account.
 * The four count pills, the Refresh button and the Display button are gone:
 * counts nobody acts on from the header, Refresh moved into the status dot's
 * menu, and the colour scheme is set in Settings › General.
 */
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
        <Link to="/" className={classes.brand} aria-label="Gateon overview">
          <img src="/gateon-logo.svg" alt="" width={26} height={26} style={{ display: "block" }} />
          <span className={classes.brandName}>GATEON</span>
        </Link>
      </Group>

      <Group gap="sm" wrap="nowrap" justify="flex-end" style={{ flex: 1, minWidth: 0 }}>
        <Box visibleFrom="sm">
          <CommandSearchButton />
        </Box>
        <AttentionBadge />
        <StatusMenu refreshing={refreshing} onRefresh={onRefresh} />
        <Tooltip label="Docs">
          <ActionIcon component={Link} to="/docs" variant="subtle" color="gray" size="lg" aria-label="Docs">
            <IconBook2 size={19} stroke={1.6} />
          </ActionIcon>
        </Tooltip>
        <AccountMenu {...props} />
      </Group>
    </Group>
  );
}
