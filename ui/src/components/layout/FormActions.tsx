// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { ReactNode } from "react";
import { Group } from "@mantine/core";
import classes from "./layout.module.css";

/** A drawer form's buttons, pinned to the bottom so Save is reachable without scrolling to the end. */
export function FormActions({ children }: { children: ReactNode }) {
  return (
    <Group justify="flex-end" gap="sm" className={classes.formActions}>
      {children}
    </Group>
  );
}
