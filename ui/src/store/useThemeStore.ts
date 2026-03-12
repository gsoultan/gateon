import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface ThemeState {
  colorScheme: 'light' | 'dark' | 'auto'
  setColorScheme: (scheme: 'light' | 'dark' | 'auto') => void
}

export const useThemeStore = create<ThemeState>()(
  persist(
    (set) => ({
      colorScheme: 'auto',
      setColorScheme: (scheme) => set({ colorScheme: scheme }),
    }),
    {
      name: 'gateon-theme-storage',
    }
  )
)
