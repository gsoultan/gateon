import React from 'react';
import { Text } from '@mantine/core';
import { format } from 'date-fns';

export function TimeDisplay() {
  const [time, setTime] = React.useState(new Date());

  React.useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 60000);
    return () => clearInterval(timer);
  }, []);

  return (
    <Text size="xs" c="dimmed">
      {format(time, 'PPP p')}
    </Text>
  );
}
