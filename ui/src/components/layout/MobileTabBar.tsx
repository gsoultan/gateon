// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Group, Text, UnstyledButton } from "@mantine/core";
import { Link, useLocation } from "@tanstack/react-router";
import { IconLayoutDashboard, IconMenu2, IconRoute, IconShieldCheck, IconTerminal2, type Icon } from "@tabler/icons-react";
import { isActivePath } from "./navigation";
import classes from "./layout.module.css";

interface MobileTabBarProps {
  /** Opens the full navigation drawer. */
  onMore: () => void;
}

const TABS: ReadonlyArray<{ label: string; to: string; icon: Icon }> = [
  { label: "Overview", to: "/", icon: IconLayoutDashboard },
  { label: "Routes", to: "/routes", icon: IconRoute },
  { label: "Security", to: "/security", icon: IconShieldCheck },
  { label: "Logs", to: "/logs", icon: IconTerminal2 },
];

/**
 * The four destinations a phone reaches for, and More for the other ten, in
 * a bar at the bottom of the screen where a thumb is. Every target is at
 * least 44 px tall.
 */
export function MobileTabBar({ onMore }: MobileTabBarProps) {
  const { pathname } = useLocation();
  return (
    <Group grow gap={0} h="100%" component="nav" aria-label="Main sections">
      {TABS.map((t) => {
        const active = isActivePath(pathname, t.to);
        return (
          <UnstyledButton
            key={t.to}
            component={Link}
            to={t.to}
            className={classes.mobileTab}
            data-active={active || undefined}
            aria-current={active ? "page" : undefined}
          >
            <t.icon size={22} stroke={active ? 2 : 1.6} />
            <Text size="xs" fw={active ? 600 : 500}>
              {t.label}
            </Text>
          </UnstyledButton>
        );
      })}
      <UnstyledButton className={classes.mobileTab} onClick={onMore} aria-label="More sections">
        <IconMenu2 size={22} stroke={1.6} />
        <Text size="xs" fw={500}>
          More
        </Text>
      </UnstyledButton>
    </Group>
  );
}
