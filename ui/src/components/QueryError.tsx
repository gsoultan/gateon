import { Alert, Button, Group, Stack, Text } from "@mantine/core";
import { IconAlertTriangle, IconRefresh } from "@tabler/icons-react";
import { getApiErrorMessage } from "../hooks/api";

interface QueryErrorProps {
  /** The error thrown by the query. */
  error: unknown;
  /** What the user was trying to see, e.g. "traces". Used in the message. */
  what: string;
  /** Retry handler — usually the query's `refetch`. */
  onRetry?: () => void;
}

/**
 * The error state for a data view.
 *
 * List pages used to destructure only `data` and `isLoading` from their query.
 * When a request failed, `data` fell back to its default empty array and the
 * page rendered its *empty* state — so "the gateway is unreachable" and "your
 * session expired" both showed up as a calm "no results". That is the worst
 * possible moment to be reassuring, because the operator is usually looking at
 * this dashboard precisely because something is wrong.
 *
 * The message is passed through getApiErrorMessage rather than rendered raw:
 * response bodies here can carry server internals, and a status code or stack
 * trace is not something to put in front of a user.
 */
export function QueryError({ error, what, onRetry }: QueryErrorProps) {
  const detail = getApiErrorMessage(error);

  return (
    <Alert
      icon={<IconAlertTriangle size={16} />}
      color="red"
      variant="light"
      radius="md"
      title={`Couldn't load ${what}`}
    >
      <Stack gap="xs">
        <Text size="sm">{detail}</Text>
        {onRetry && (
          <Group>
            <Button
              size="xs"
              variant="light"
              color="red"
              leftSection={<IconRefresh size={14} />}
              onClick={onRetry}
            >
              Try again
            </Button>
          </Group>
        )}
      </Stack>
    </Alert>
  );
}
