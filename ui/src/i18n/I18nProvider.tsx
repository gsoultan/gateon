import { useEffect, type ReactNode } from "react";
import { usePreferencesStore } from "../store/usePreferencesStore";
import { DEFAULT_LANGUAGE, normalizeLanguage } from "./locales";

interface I18nProviderProps {
  children: ReactNode;
}

/**
 * I18nProvider keeps the document's `lang` attribute in sync with the persisted
 * language preference (for accessibility and correct browser behaviour). The
 * `t` function itself is provided by the `useTranslation` hook, which reads the
 * same store, so no React context is required.
 */
export function I18nProvider({ children }: I18nProviderProps) {
  const stored = usePreferencesStore((state) => state.language);
  const language = normalizeLanguage(stored ?? DEFAULT_LANGUAGE);

  useEffect(() => {
    document.documentElement.lang = language;
  }, [language]);

  return <>{children}</>;
}
