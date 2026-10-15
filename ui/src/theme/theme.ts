// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { createTheme, type MantineColorsTuple } from "@mantine/core";

const brand: MantineColorsTuple = [
  "#e8f2ff",
  "#d0e3ff",
  "#a1c5fd",
  "#6ea5fb",
  "#448af9",
  "#2a78f8",
  "#1a6ff9",
  "#0b5ede",
  "#0053c7",
  "#0047b0",
];

// A neutral, slightly cool dark scale. The surfaces are far enough apart that
// a card on the page and a field in the card read as separate layers without
// a border doing all the work.
const dark: MantineColorsTuple = [
  "#d6d8de",
  "#b3b6c0",
  "#8d91a0",
  "#686c7c",
  "#454857",
  "#33363f",
  "#262830",
  "#1c1d24",
  "#15161b",
  "#0f1014",
];

const sansSerif = "Inter, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif";

/**
 * The dashboard's single source of look and spacing. Pages take their density
 * from here rather than setting padding, radius and input size one component
 * at a time, so a form reads the same on every page.
 */
export const theme = createTheme({
  primaryColor: "brand",
  // Shade 5 in dark mode: shade 8 was close enough to the dark surfaces that
  // an active navigation item or a filled button barely stood out.
  primaryShade: { light: 6, dark: 5 },
  autoContrast: true,
  cursorType: "pointer",
  focusRing: "auto",
  fontFamily: sansSerif,
  fontFamilyMonospace: "'JetBrains Mono', SFMono-Regular, Menlo, Monaco, Consolas, monospace",
  defaultRadius: "md",
  white: "#fff",
  black: "#101114",
  colors: { brand, dark },
  headings: {
    fontFamily: sansSerif,
    fontWeight: "700",
    sizes: {
      h1: { fontSize: "1.75rem", lineHeight: "1.25" },
      h2: { fontSize: "1.5rem", lineHeight: "1.3" },
      h3: { fontSize: "1.25rem", lineHeight: "1.35" },
      h4: { fontSize: "1.0625rem", lineHeight: "1.4" },
      h5: { fontSize: "0.9375rem", lineHeight: "1.45" },
      h6: { fontSize: "0.875rem", lineHeight: "1.5" },
    },
  },
  shadows: {
    xs: "0 1px 2px rgba(16, 17, 20, 0.04)",
    sm: "0 1px 3px rgba(16, 17, 20, 0.06), 0 1px 2px rgba(16, 17, 20, 0.04)",
    md: "0 4px 12px -2px rgba(16, 17, 20, 0.08), 0 2px 4px -2px rgba(16, 17, 20, 0.04)",
    lg: "0 12px 24px -6px rgba(16, 17, 20, 0.12), 0 4px 8px -4px rgba(16, 17, 20, 0.06)",
    xl: "0 24px 40px -12px rgba(16, 17, 20, 0.18)",
  },
  components: {
    Card: {
      defaultProps: { radius: "lg", withBorder: true, shadow: "xs", padding: "lg" },
    },
    Paper: {
      defaultProps: { radius: "md", withBorder: true },
    },
    Button: {
      defaultProps: { radius: "md", loaderProps: { type: "dots" } },
      styles: { root: { fontWeight: 600 } },
    },
    ActionIcon: {
      defaultProps: { radius: "md" },
    },
    // One rhythm for every field: label, then description, then the control,
    // with room between them. Inputs used to set radius and size one by one,
    // so the same form mixed three heights and two corner shapes.
    InputWrapper: {
      styles: {
        label: { fontWeight: 600, marginBottom: 4 },
        description: { marginBottom: 6, lineHeight: 1.45 },
        error: { marginTop: 6 },
      },
    },
    Input: {
      defaultProps: { radius: "md" },
    },
    TextInput: { defaultProps: { radius: "md" } },
    PasswordInput: { defaultProps: { radius: "md" } },
    NumberInput: { defaultProps: { radius: "md" } },
    Select: { defaultProps: { radius: "md", comboboxProps: { shadow: "md" } } },
    MultiSelect: { defaultProps: { radius: "md", comboboxProps: { shadow: "md" } } },
    TagsInput: { defaultProps: { radius: "md", comboboxProps: { shadow: "md" } } },
    Textarea: { defaultProps: { radius: "md" } },
    Switch: {
      styles: { label: { fontWeight: 500 }, description: { marginTop: 2 } },
    },
    Checkbox: {
      styles: { label: { fontWeight: 500 } },
    },
    Badge: {
      defaultProps: { radius: "sm", variant: "light" },
      styles: { root: { fontWeight: 600, letterSpacing: 0.2 } },
    },
    Modal: {
      defaultProps: {
        radius: "lg",
        padding: "lg",
        centered: true,
        overlayProps: { backgroundOpacity: 0.45, blur: 2 },
        transitionProps: { transition: "pop", duration: 150 },
      },
      styles: { title: { fontWeight: 700, fontSize: "var(--mantine-font-size-lg)" } },
    },
    Drawer: {
      defaultProps: { overlayProps: { backgroundOpacity: 0.45, blur: 2 } },
      styles: { title: { fontWeight: 700, fontSize: "var(--mantine-font-size-lg)" } },
    },
    Tooltip: {
      defaultProps: { openDelay: 250, withArrow: true, arrowSize: 6 },
    },
    Menu: {
      defaultProps: { radius: "md", shadow: "md" },
    },
    Popover: {
      defaultProps: { radius: "md", shadow: "md" },
    },
    Table: {
      defaultProps: { verticalSpacing: "sm", horizontalSpacing: "md" },
    },
    Tabs: {
      styles: { tab: { fontWeight: 600 } },
    },
    Alert: {
      defaultProps: { radius: "md" },
    },
    Notification: {
      defaultProps: { radius: "md" },
    },
    Skeleton: {
      defaultProps: { radius: "md" },
    },
  },
});
