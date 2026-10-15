# 68. The dashboard takes its look from one theme and one page header

Date: 2026-10-14

## Status

Accepted.

## Context

Every page set its own look. Titles were `fw={800}` with a letter spacing of
`-1`, `-0.5` or none; inputs set `radius` and `size` one by one; cards mixed
`padding="md"`, `"lg"` and `"xl"`. Nothing was wrong on any one page, but no
two lined up, and a form on one page had different field heights and corner
shapes from the same form on the next.

The shell decided light or dark with `useMantineColorScheme().colorScheme ===
"dark"`. That value is the operator's *setting*, and the dashboard defaults
to `"auto"`, so on a system in dark mode the comparison was false: the header,
sidebar, health bar and topology nodes drew light-mode colours around a dark
page. That was the default experience for anyone whose system was dark.

## Decision

- **`ui/src/theme/`** holds the Mantine theme. Component defaults (radius,
  card padding, the label → description → control rhythm of every field,
  modal and table defaults) live there, not on each component.
- **`ui/src/components/layout/`** holds the shell's parts: `AppHeader`,
  `AppNavbar`, the navigation list in `navigation.ts`, and `PageHeader`, which
  every page uses for its title, one-line description and main actions.
- **Light or dark is decided by CSS** on `[data-mantine-color-scheme]`, or by
  `useComputedColorScheme()` where a value is needed in JavaScript (the
  topology graph). `src/theme/colorScheme.test.ts` fails if any source file
  compares the setting to `"dark"` or `"light"` again.

## Consequences

- A change to density, radius or field spacing is one edit in the theme.
  A page that overrides a theme default should say why.
- New pages start from `PageHeader`; a page with its own title markup is drift.
- The sidebar's sections and their filters (ClamAV only when installed, Users
  and API Tokens for administrators only) are a pure function with tests, so
  the shell no longer repeats the same link markup three times.
