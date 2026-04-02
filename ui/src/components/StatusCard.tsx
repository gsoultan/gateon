import { Card, Group, Text, Title, Notification, Badge, Divider, Stack, SimpleGrid, Paper } from '@mantine/core'
import { IconActivity, IconRoute, IconClock, IconVersions } from '@tabler/icons-react'
import { useGateonStatus } from '../hooks/useGateon'

export default function StatusCard() {
  const { data: statusData, error: statusError, isLoading: isStatusLoading } = useGateonStatus()

  const stats = [
    { label: 'Version', value: statusData?.version || 'N/A', icon: IconVersions, color: 'blue' },
    { label: 'System Uptime', value: statusData?.uptime ? formatUptime(statusData.uptime) : '0s', icon: IconClock, color: 'teal' },
    { label: 'CPU Usage', value: statusData?.cpu_usage !== undefined ? `${statusData.cpu_usage.toFixed(1)}%` : '0%', icon: IconActivity, color: 'blue' },
    { label: 'Memory Usage', value: statusData?.memory_usage_percent !== undefined ? `${statusData.memory_usage_percent.toFixed(1)}%` : '0%', icon: IconActivity, color: 'orange' },
  ]

  const counts = [
    { label: 'Routes', value: statusData?.routes_count ?? 0, color: 'indigo' },
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
          <Paper key={c.label} p="md" radius="lg" withBorder shadow="xs">
            <Stack gap={0}>
              <Text size="xs" c="dimmed" fw={800} style={{ textTransform: 'uppercase', letterSpacing: 1 }}>{c.label}</Text>
              <Text size="xl" fw={900} c={`${c.color}.6`}>{c.value}</Text>
            </Stack>
          </Paper>
        ))}
      </SimpleGrid>
      
      <Card shadow="xs" padding="xl" radius="lg" withBorder>
        <Stack gap="xl">
          <Group justify="space-between">
            <Group gap="md">
              <Paper p="xs" radius="md" bg="indigo.6" shadow="md">
                <IconActivity size={24} color="white" />
              </Paper>
              <div>
                <Title order={3} fw={800} style={{ letterSpacing: -0.5 }}>Gateon Instances</Title>
                <Text c="dimmed" size="sm" fw={500}>Core engine status and operational metrics</Text>
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

          <Divider variant="dashed" />

          <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="xl">
            {stats.map((stat) => (
              <Paper key={stat.label} p="md" radius="md" withBorder bg="var(--mantine-color-default-hover)">
                <Group>
                  <stat.icon size={24} color={`var(--mantine-color-${stat.color}-6)`} />
                  <div>
                    <Text size="xs" c="dimmed" fw={800} style={{ textTransform: 'uppercase', letterSpacing: 1 }}>
                      {stat.label}
                    </Text>
                    <Text fw={700} size="lg">{stat.value}</Text>
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

function formatBytes(bytes: number) {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}
