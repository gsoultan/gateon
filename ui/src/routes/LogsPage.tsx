import { Stack } from '@mantine/core'
import LiveLogs from '../components/LiveLogs'

export default function LogsPage() {
  return (
    <Stack gap="md">
      <LiveLogs height={500} />
    </Stack>
  )
}
