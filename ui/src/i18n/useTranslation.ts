import { useCallback } from "react";
import { usePreferencesStore } from "../store/usePreferencesStore";
import { en, type TranslationKey } from "./en";
import {
  DEFAULT_LANGUAGE,
  RESOURCES,
  normalizeLanguage,
  type Language,
} from "./locales";

/** Values that can be interpolated into a translated string. */
export type TranslationParams = Record<string, string | number>;

/** A bound translate function: looks up `key` and interpolates `{{params}}`. */
export type TranslateFn = (key: TranslationKey, params?: TranslationParams) => string;

/**
 * Resolves a key for a language, falling back to English (then the raw key) so
 * a missing translation never blanks the UI.
 */
function resolve(language: Language, key: TranslationKey): string {
  return RESOURCES[language]?.[key] ?? en[key] ?? key;
}

/** Replaces `{{name}}` placeholders with the matching param value. */
function interpolate(template: string, params?: TranslationParams): string {
  if (!params) return template;
  return template.replace(/\{\{(\w+)\}\}/g, (match, name: string) => {
    const value = params[name];
    return value === undefined ? match : String(value);
  });
}

/**
 * useTranslation returns the current `language` and a memoized `t` function.
 * Language is sourced from the persisted preferences store, so switching it
 * anywhere re-renders all consumers. Lookups are type-safe (`TranslationKey`)
 * and fall back to English for partially-translated locales.
 */
export function useTranslation(): { language: Language; t: TranslateFn } {
  const stored = usePreferencesStore((state) => state.language);
  const language = normalizeLanguage(stored ?? DEFAULT_LANGUAGE);

  const t = useCallback<TranslateFn>(
    (key, params) => interpolate(resolve(language, key), params),
    [language],
  );

  return { language, t };
}
