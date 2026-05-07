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
      <ThemeIcon color={item.color} variant="light" size={42} radius="md">
        <item.icon style={{ width: rem(22), height: rem(22) }} stroke={1.5} />
      </ThemeIcon>
      <Text size="xs" mt={8} fw={700} c="dimmed" style={{ textTransform: 'uppercase', letterSpacing: 0.5 }}>
        {item.title}
      </Text>
    </UnstyledButton>
  ));

  return (
    <Paper withBorder radius="md" p="lg" shadow="xs">
      <Group justify="space-between" mb="lg">
        <div>
          <Title order={5} fw={800} style={{ letterSpacing: -0.2 }}>Quick Actions</Title>
          <Text size="xs" c="dimmed">Common management tasks</Text>
        </div>
      </Group>
      <SimpleGrid cols={3} spacing="md">
        {items}
      </SimpleGrid>
    </Paper>
  );
}
