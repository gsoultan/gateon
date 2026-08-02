import { useMediaQuery } from '@mantine/hooks';
import { useMantineTheme } from '@mantine/core';

export function useIsMobile() {
  const theme = useMantineTheme();
  return useMediaQuery(`(max-width: ${theme.breakpoints.sm})`);
}

export function useIsTablet() {
  const theme = useMantineTheme();
  return useMediaQuery(`(max-width: ${theme.breakpoints.md})`);
}
