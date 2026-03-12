import { Card, Title, Text } from '@mantine/core'

export default function LogsPage() {
  return (
    <Card withBorder>
      <Title order={4}>Logs</Title>
      <Text c="dimmed" size="sm">A richer logs view with filtering will appear here.</Text>
    </Card>
  )
}
