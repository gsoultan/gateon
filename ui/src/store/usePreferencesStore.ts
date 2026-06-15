import { create } from "zustand";
import { persist } from "zustand/middleware";
import { DEFAULT_LANGUAGE, type Language } from "../i18n/locales";

/** Table row density used across data tables. */
export type TableDensity = "comfortable" | "compact";

interface PreferencesState {
  /** Whether the desktop sidebar is collapsed (icon-only). */
  sidebarCollapsed: boolean;
  /** Preferred density for data tables. */
  tableDensity: TableDensity;
  /** Whether the user dismissed the onboarding checklist on the dashboard. */
  onboardingDismissed: boolean;
  /** Preferred UI language (BCP-47-ish short code, e.g. "en"). */
  language: Language;
  setSidebarCollapsed: (collapsed: boolean) => void;
  toggleSidebar: () => void;
  setTableDensity: (density: TableDensity) => void;
  setOnboardingDismissed: (dismissed: boolean) => void;
  setLanguage: (language: Language) => void;
}

/**
 * usePreferencesStore holds user-level UI preferences that should survive
 * reloads and navigation. It persists to localStorage via Zustand's `persist`
 * middleware so the experience feels consistent across sessions.
 */
export const usePreferencesStore = create<PreferencesState>()(
  persist(
    (set) => ({
      sidebarCollapsed: false,
      tableDensity: "comfortable",
      onboardingDismissed: false,
      language: DEFAULT_LANGUAGE,
      setSidebarCollapsed: (collapsed) => set({ sidebarCollapsed: collapsed }),
      toggleSidebar: () =>
        set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
      setTableDensity: (density) => set({ tableDensity: density }),
      setOnboardingDismissed: (dismissed) =>
        set({ onboardingDismissed: dismissed }),
      setLanguage: (language) => set({ language }),
    }),
    {
      name: "gateon-preferences",
      version: 2,
    },
  ),
);
