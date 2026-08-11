// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

export { I18nProvider } from "./I18nProvider";
export { useTranslation } from "./useTranslation";
export type { TranslateFn, TranslationParams } from "./useTranslation";
export type { TranslationKey } from "./en";
export {
  SUPPORTED_LANGUAGES,
  DEFAULT_LANGUAGE,
  LANGUAGE_LABELS,
  normalizeLanguage,
} from "./locales";
export type { Language } from "./locales";
