import { Box } from '@mantine/core'
import LiveLogs from '../components/LiveLogs'

export default function LogsPage() {
  // Fill the viewport below the app header. Offsets: AppShell header height,
  // AppShell.Main top+bottom padding (spacing "md"), and the content wrapper's
  // 40px paddingBottom (see Shell.tsx). dvh keeps mobile browser chrome honest.
  return (
    <Box
      style={{
        height:
          'calc(100dvh - var(--app-shell-header-height, 60px) - 2 * var(--mantine-spacing-md, 16px) - 40px)',
        minHeight: 320,
      }}
    >
      <LiveLogs fill />
    </Box>
  )
}
