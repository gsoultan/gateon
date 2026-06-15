import { en, type TranslationResources } from "./en";

/**
 * Supported UI languages. Add a new entry here (plus its resource map below)
 * to localize the dashboard — every consumer reads from this single registry.
 */
export const SUPPORTED_LANGUAGES = ["en", "id"] as const;

export type Language = (typeof SUPPORTED_LANGUAGES)[number];

/** The default language used before a preference is set and as the fallback. */
export const DEFAULT_LANGUAGE: Language = "en";

/** Human-readable labels for the language selector. */
export const LANGUAGE_LABELS: Record<Language, string> = {
  en: "English",
  id: "Bahasa Indonesia",
};

/**
 * Partial Indonesian catalog. Missing keys fall back to English at lookup time,
 * which lets translations land incrementally without breaking the UI.
 */
const id: TranslationResources = {
  "common.language": "Bahasa",
  "appearance.title": "Tampilan",
  "appearance.description": "Sesuaikan tampilan dan nuansa dasbor.",
  "appearance.themeMode": "Mode Tema",
  "appearance.theme.light": "Terang",
  "appearance.theme.dark": "Gelap",
  "appearance.theme.system": "Sistem",
  "appearance.tableDensity": "Kerapatan Tabel",
  "appearance.tableDensity.description":
    "Pilih seberapa banyak ruang vertikal yang digunakan tabel data.",
  "appearance.density.comfortable": "Nyaman",
  "appearance.density.compact": "Padat",
  "appearance.language.description": "Pilih bahasa yang digunakan di dasbor.",
};

/** Resource catalogs keyed by language; `en` is always complete. */
export const RESOURCES: Record<Language, TranslationResources> = {
  en,
  id,
};

/** Narrows an arbitrary string to a supported `Language` (else the default). */
export function normalizeLanguage(value: string | null | undefined): Language {
  return SUPPORTED_LANGUAGES.includes(value as Language)
    ? (value as Language)
    : DEFAULT_LANGUAGE;
}
