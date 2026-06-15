import {
  Button,
  Center,
  Code,
  Group,
  Paper,
  Stack,
  Text,
  ThemeIcon,
  Title,
} from "@mantine/core";
import { IconAlertTriangle, IconRefresh } from "@tabler/icons-react";

export type ErrorFallbackProps = {
  error: unknown;
  /** Short, stable id to correlate the failure in logs/support tickets. */
  errorId: string;
  /** Reset the boundary / retry rendering the failed subtree. */
  onReset?: () => void;
};

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  return "An unexpected error occurred.";
}

/**
 * ErrorFallback is the shared presentational UI rendered when a render error is
 * caught (by the top-level boundary or a route errorComponent). It offers a
 * friendly explanation plus Reload/Retry actions and an error id for support.
 */
export function ErrorFallback({ error, errorId, onReset }: ErrorFallbackProps) {
  return (
    <Center mih="60vh" p="md">
      <Paper withBorder shadow="sm" radius="md" p="xl" maw={520} w="100%">
        <Stack gap="md" align="center">
          <ThemeIcon color="red" variant="light" size={56} radius="xl">
            <IconAlertTriangle size={30} />
          </ThemeIcon>
          <Stack gap={4} align="center">
            <Title order={3} ta="center">
              Something went wrong
            </Title>
            <Text c="dimmed" ta="center" size="sm">
              The page failed to render. You can retry or reload the app. If the
              problem persists, share the error id below with support.
            </Text>
          </Stack>
          <Code block w="100%">
            {errorMessage(error)}
          </Code>
          <Text c="dimmed" size="xs">
            Error id: <Code>{errorId}</Code>
          </Text>
          <Group justify="center" gap="sm">
            {onReset && (
              <Button variant="default" onClick={onReset}>
                Try again
              </Button>
            )}
            <Button
              leftSection={<IconRefresh size={16} />}
              onClick={() => window.location.reload()}
            >
              Reload
            </Button>
          </Group>
        </Stack>
      </Paper>
    </Center>
  );
}
