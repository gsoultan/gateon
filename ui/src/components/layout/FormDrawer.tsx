// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { ReactNode } from "react";
import { Drawer } from "@mantine/core";
import { useIsMobile } from "../../hooks/useMobile";
import classes from "./layout.module.css";

/** How much room a form needs: a single column, two columns, or a form with a side preview. */
export type FormDrawerWidth = "narrow" | "wide" | "full";

const WIDTHS: Record<FormDrawerWidth, number | string> = {
  narrow: 560,
  wide: 760,
  full: "min(1200px, 92vw)",
};

interface FormDrawerProps {
  opened: boolean;
  onClose: () => void;
  title: ReactNode;
  width?: FormDrawerWidth;
  children: ReactNode;
}

/**
 * The side panel every create and edit form opens in. The three drawers it
 * replaces each set their own width, padding and header border, one of them
 * a dark-mode colour that drew a dark line in light mode, and none left room
 * between the header and the first field.
 */
export function FormDrawer({ opened, onClose, title, width = "narrow", children }: FormDrawerProps) {
  const isMobile = useIsMobile();
  return (
    <Drawer
      opened={opened}
      onClose={onClose}
      title={title}
      position="right"
      size={isMobile ? "100%" : WIDTHS[width]}
      padding="xl"
      classNames={{ header: classes.drawerHeader, body: classes.drawerBody }}
    >
      {children}
    </Drawer>
  );
}
