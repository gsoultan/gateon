// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

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
