// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { memo } from "react";
import { Paper, Text, Stack, UnstyledButton, Group, ThemeIcon, rem, Title } from "@mantine/core";
import { 
  IconRoute, 
  IconServer, 
  IconShieldLock, 
  IconSettings,
  IconActivity,
  IconChevronRight,
} from "@tabler/icons-react";
import { Link } from "@tanstack/react-router";
import classes from "./QuickActions.module.css";
import { usePermissions } from "../../hooks/usePermissions";
import { CREATE_SEARCH } from "../layout";

// "Add" opens the page's create form; it is offered only to a role that can
// create, and a viewer is not shown a button that cannot do what it says.
const actions = [
  { title: "Add route", icon: IconRoute, color: "blue", to: "/routes", create: true },
  { title: "Add service", icon: IconServer, color: "teal", to: "/services", create: true },
  { title: "Certificates", icon: IconShieldLock, color: "indigo", to: "/tls" },
  { title: "Real-time metrics", icon: IconActivity, color: "orange", to: "/metrics-dashboard" },
  { title: "System settings", icon: IconSettings, color: "gray", to: "/settings" },
];

export const QuickActions = memo(function QuickActions() {
  const { canWrite } = usePermissions();
  const shown = actions.filter((a) => !("create" in a) || canWrite);
  return (
    <Paper withBorder radius="lg" p="lg">
      <Title order={5} mb={2}>
        Quick actions
      </Title>
      <Text size="sm" c="dimmed" mb="md">
        Common management tasks
      </Text>
      <Stack gap={4}>
        {shown.map((item) => (
          <UnstyledButton
            key={item.title}
            className={classes.item}
            component={Link}
            to={item.to}
            // Neither route declares a search schema, so the router types its
            // search as never; the page reads it with useCreateFromLink.
            search={("create" in item ? () => CREATE_SEARCH : undefined) as never}
          >
            <Group gap="sm" wrap="nowrap">
              <ThemeIcon color={item.color} variant="light" size={34} radius="md">
                <item.icon style={{ width: rem(18), height: rem(18) }} stroke={1.6} />
              </ThemeIcon>
              <Text size="sm" fw={500} style={{ flex: 1 }}>
                {item.title}
              </Text>
              <IconChevronRight size={16} className={classes.chevron} />
            </Group>
          </UnstyledButton>
        ))}
      </Stack>
    </Paper>
  );
});
