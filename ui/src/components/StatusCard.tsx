import { Card, Group, Text, Title, Notification, Badge, Divider, Stack, SimpleGrid, Paper, Progress, Box, ThemeIcon } from '@mantine/core'
import { IconActivity, IconRoute, IconClock, IconVersions, IconCpu, IconDeviceDesktop } from '@tabler/icons-react'
import { useGateonStatus } from '../hooks/useGateon'
import { formatBytes } from '../utils/format'

export default function StatusCard() {
  const { data: statusData, error: statusError, isLoading: isStatusLoading } = useGateonStatus()

  const stats = [
    { label: 'Version', value: statusData?.version || 'N/A', icon: IconVersions, color: 'blue' },
    { label: 'System Uptime', value: statusData?.uptime ? formatUptime(statusData.uptime) : '0s', icon: IconClock, color: 'teal' },
    { label: 'CPU Usage', value: statusData?.cpu_usage !== undefined ? `${statusData.cpu_usage.toFixed(1)}%` : '0%', icon: IconActivity, color: 'blue' },
    { label: 'Memory Usage', value: statusData?.memory_usage_percent !== undefined ? `${statusData.memory_usage_percent.toFixed(1)}%` : '0%', icon: IconActivity, color: 'orange' },
  ]

  const counts = [
    { label: 'Routes', value: statusData?.routes_count ?? 0, color: 'brand' },
    { label: 'Services', value: statusData?.services_count ?? 0, color: 'blue' },
    { label: 'EntryPoints', value: statusData?.entry_points_count ?? 0, color: 'teal' },
    { label: 'Middlewares', value: statusData?.middlewares_count ?? 0, color: 'orange' },
  ]

  if (isStatusLoading) return (
    <Card shadow="sm" padding="xl" radius="lg" withBorder>
      <Stack gap="md">
        <Text>Loading status...</Text>
      </Stack>
    </Card>
  )

  return (
    <Stack gap="md">
      {statusError && (
        <Notification color="red" title="Error" mb="md" withCloseButton={false}>
          {statusError.toString()}
        </Notification>
      )}
      
      <SimpleGrid cols={{ base: 2, md: 4 }} spacing="md">
        {counts.map((c) => (
          <Paper key={c.label} p="md" radius="md" withBorder shadow="xs" style={{ transition: 'all 0.2s ease', borderLeft: `4px solid var(--mantine-color-${c.color}-6)` }} className="hover:shadow-md">
            <Stack gap={0}>
              <Text size="xs" c="dimmed" fw={700} style={{ textTransform: 'uppercase', letterSpacing: 0.5 }}>{c.label}</Text>
              <Text size="xl" fw={800} c={`${c.color}.6`} style={{ letterSpacing: -0.5 }}>{c.value}</Text>
            </Stack>
          </Paper>
        ))}
      </SimpleGrid>
      
      <Card shadow="xs" padding="xl" radius="md" withBorder>
        <Stack gap="xl">
          <Group justify="space-between">
            <Group gap="md">
              <ThemeIcon variant="filled" size={42} radius="md" color="brand">
                <IconActivity size={24} stroke={1.5} />
              </ThemeIcon>
              <div>
                <Title order={3} fw={800} style={{ letterSpacing: -0.5 }}>System Health</Title>
                <Text size="sm" c="dimmed">Live performance metrics and system status</Text>
              </div>
            </Group>
            <Badge 
              size="lg" 
              color={statusData?.status === 'running' ? 'green' : 'red'} 
              variant="light" 
              px="xl" 
              radius="xl"
              styles={{ root: { height: 32, fontWeight: 700 } }}
            >
              {statusData?.status?.toUpperCase() || 'UNKNOWN'}
            </Badge>
          </Group>

          <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="lg">
            <Box>
              <Group justify="space-between" mb={6}>
                <Text size="xs" fw={700} c="dimmed" style={{ textTransform: 'uppercase' }}>CPU Load</Text>
                <Text size="xs" fw={700}>{statusData?.cpu_usage?.toFixed(1) || 0}%</Text>
              </Group>
              <Progress value={statusData?.cpu_usage || 0} size="md" radius="xl" color="brand" animated />
            </Box>
            <Box>
              <Group justify="space-between" mb={6}>
                <Text size="xs" fw={700} c="dimmed" style={{ textTransform: 'uppercase' }}>Memory Utilization</Text>
                <Text size="xs" fw={700}>{statusData?.memory_usage_percent?.toFixed(1) || 0}%</Text>
              </Group>
              <Progress value={statusData?.memory_usage_percent || 0} size="md" radius="xl" color="orange" animated />
            </Box>
          </SimpleGrid>

          <Divider variant="dashed" />

          <SimpleGrid cols={{ base: 1, sm: 4 }} spacing="md">
            {stats.map((stat) => (
              <Paper key={stat.label} p="sm" radius="md" withBorder bg="var(--mantine-color-body)" style={{ borderStyle: 'dashed' }}>
                <Group gap="sm">
                  <ThemeIcon variant="light" color={stat.color} size="md">
                    <stat.icon size={18} stroke={1.5} />
                  </ThemeIcon>
                  <div>
                    <Text size="xs" c="dimmed" fw={700} style={{ textTransform: 'uppercase', letterSpacing: 0.5 }}>
                      {stat.label}
                    </Text>
                    <Text fw={700} size="sm">{stat.value}</Text>
                  </div>
                </Group>
              </Paper>
            ))}
          </SimpleGrid>
        </Stack>
      </Card>
    </Stack>
  )
}

function formatUptime(seconds: number) {
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  return `${hours}h ${minutes}m`
}
