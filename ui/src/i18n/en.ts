/**
 * English (default) translation resources.
 *
 * This is the canonical, complete locale: its shape defines the `TranslationKey`
 * type, so every other locale is type-checked against it and partial locales
 * gracefully fall back to these strings. Keys are dot-namespaced by feature
 * (e.g. `appearance.title`) to keep the catalog navigable as it grows.
 */
export const en = {
  "common.language": "Language",

  "appearance.title": "Appearance",
  "appearance.description": "Customize the look and feel of the dashboard.",
  "appearance.themeMode": "Theme Mode",
  "appearance.theme.light": "Light",
  "appearance.theme.dark": "Dark",
  "appearance.theme.system": "System",
  "appearance.tableDensity": "Table Density",
  "appearance.tableDensity.description":
    "Choose how much vertical space data tables use.",
  "appearance.density.comfortable": "Comfortable",
  "appearance.density.compact": "Compact",
  "appearance.language.description":
    "Choose the language used across the dashboard.",
} as const;

/** A translatable string key, derived from the canonical English catalog. */
export type TranslationKey = keyof typeof en;

/** The shape every locale must (partially) satisfy. */
export type TranslationResources = Partial<Record<TranslationKey, string>>;
