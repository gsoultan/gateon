// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Fragment } from "react";
import { AppShell, Badge, Divider, Group, NavLink, ScrollArea, Stack, Text, Tooltip } from "@mantine/core";
import { Link, useLocation } from "@tanstack/react-router";
import { ConnectionStatus } from "../ConnectionStatus";
import { GlobalHealthBar } from "../GlobalHealthBar";
import { isActivePath, type NavSection } from "./navigation";
import classes from "./layout.module.css";

interface AppNavbarProps {
  sections: NavSection[];
  /** False when the desktop sidebar is collapsed to icons. */
  expanded: boolean;
  isMobile: boolean;
  version: string | undefined;
}

export function AppNavbar({ sections, expanded, isMobile, version }: AppNavbarProps) {
  const { pathname } = useLocation();

  return (
    <>
      <AppShell.Section grow component={ScrollArea} scrollbarSize={6} px="sm" py="sm">
        {isMobile && (
          <Stack gap="xs" px={4} pb="sm">
            <Group justify="space-between">
              <Text size="xs" fw={700} c="dimmed" tt="uppercase">
                System status
              </Text>
              <ConnectionStatus />
            </Group>
            <GlobalHealthBar wrap />
            <Divider mt="xs" />
          </Stack>
        )}
        <nav aria-label="Main navigation">
          {sections.map((section, index) => (
            <Fragment key={section.title}>
              {expanded ? (
                <div className={classes.sectionTitle}>{section.title}</div>
              ) : (
                index > 0 && <Divider className={classes.collapsedDivider} />
              )}
              <Stack gap={2}>
                {section.items.map((item) => (
                  <Tooltip
                    key={item.to}
                    label={item.label}
                    position="right"
                    disabled={expanded}
                    offset={12}
                  >
                    <NavLink
                      component={Link}
                      to={item.to}
                      label={expanded ? item.label : undefined}
                      aria-label={expanded ? undefined : item.label}
                      leftSection={<item.icon size={19} stroke={1.6} />}
                      active={isActivePath(pathname, item.to)}
                      variant="light"
                      classNames={{
                        root: expanded ? classes.navLink : `${classes.navLink} ${classes.navLinkCollapsed}`,
                        section: classes.navLinkSection,
                      }}
                    />
                  </Tooltip>
                ))}
              </Stack>
            </Fragment>
          ))}
        </nav>
      </AppShell.Section>

      <AppShell.Section className={classes.navFooter} px="md" pb="sm">
        {expanded ? (
          <Group justify="space-between" wrap="nowrap">
            <Text size="xs" c="dimmed" truncate>
              Gateon {version ? `· ${version}` : ""}
            </Text>
            <Badge size="xs" variant="outline" color="gray">
              OSS
            </Badge>
          </Group>
        ) : (
          <Group justify="center">
            <Badge size="xs" variant="outline" color="gray">
              OSS
            </Badge>
          </Group>
        )}
      </AppShell.Section>
    </>
  );
}
