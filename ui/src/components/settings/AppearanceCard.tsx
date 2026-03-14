import { Card, Title, Text, Stack, SegmentedControl, Group, Paper, Center } from "@mantine/core";
import { IconPalette, IconSun, IconMoon, IconDeviceDesktop } from "@tabler/icons-react";

interface AppearanceCardProps {
  colorScheme: "light" | "dark" | "auto";
  setColorScheme: (value: "light" | "dark" | "auto") => void;
}

export function AppearanceCard({ colorScheme, setColorScheme }: AppearanceCardProps) {
  return (
    <Card withBorder padding="xl" radius="lg" shadow="xs">
      <Stack gap="lg">
        <Group gap="md">
          <Paper p="xs" radius="md" bg="violet.6">
            <IconPalette size={20} color="white" />
          </Paper>
          <div>
            <Title order={4} fw={700}>
              Appearance
            </Title>
            <Text c="dimmed" size="xs">
              Customize the look and feel of the dashboard.
            </Text>
          </div>
        </Group>
        <Stack gap="xs">
          <Text size="sm" fw={700}>
            Theme Mode
          </Text>
          <SegmentedControl
            value={colorScheme}
            onChange={(value: "light" | "dark" | "auto") => setColorScheme(value)}
            data={[
              {
                value: "light",
                label: (
                  <Center style={{ gap: 10 }}>
                    <IconSun size={16} />
                    <span>Light</span>
                  </Center>
                ),
              },
              {
                value: "dark",
                label: (
                  <Center style={{ gap: 10 }}>
                    <IconMoon size={16} />
                    <span>Dark</span>
                  </Center>
                ),
              },
              {
                value: "auto",
                label: (
                  <Center style={{ gap: 10 }}>
                    <IconDeviceDesktop size={16} />
                    <span>System</span>
                  </Center>
                ),
              },
            ]}
            radius="md"
            size="md"
            fullWidth
          />
        </Stack>
      </Stack>
    </Card>
  );
}
