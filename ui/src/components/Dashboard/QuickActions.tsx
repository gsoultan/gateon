import { Paper, Text, SimpleGrid, UnstyledButton, Group, ThemeIcon, rem } from "@mantine/core";
import { 
  IconRoute, 
  IconServer, 
  IconShieldLock, 
  IconSettings,
  IconPlus,
  IconActivity
} from "@tabler/icons-react";
import { Link } from "@tanstack/react-router";
import classes from "./QuickActions.module.css";

const actions = [
  { title: "Add Route", icon: IconRoute, color: "blue", to: "/routes", action: "add" },
  { title: "Add Service", icon: IconServer, color: "teal", to: "/services", action: "add" },
  { title: "Certificates", icon: IconShieldLock, color: "indigo", to: "/certificates" },
  { title: "Real-time Metrics", icon: IconActivity, color: "orange", to: "/metrics" },
  { title: "System Settings", icon: IconSettings, color: "gray", to: "/settings" },
];

export function QuickActions() {
  const items = actions.map((item) => (
    <UnstyledButton key={item.title} className={classes.item} component={Link} to={item.to}>
      <ThemeIcon color={item.color} variant="light" size={44} radius="md">
        <item.icon style={{ width: rem(26), height: rem(26) }} stroke={1.5} />
      </ThemeIcon>
      <Text size="xs" mt={7} fw={500}>
        {item.title}
      </Text>
    </UnstyledButton>
  ));

  return (
    <Paper withBorder radius="md" p="md">
      <Group justify="space-between" mb="md">
        <Text fw={700} size="sm">Quick Actions</Text>
      </Group>
      <SimpleGrid cols={3} spacing="sm">
        {items}
      </SimpleGrid>
    </Paper>
  );
}
