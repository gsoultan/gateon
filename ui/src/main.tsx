// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import React from 'react'
import ReactDOM from 'react-dom/client'
import { MantineProvider } from '@mantine/core'
import { QueryClientProvider } from '@tanstack/react-query'
import { queryClient } from './queryClient'
import { Notifications } from '@mantine/notifications'
import App from './App'
import { ErrorBoundary } from './components/ErrorBoundary'
import { I18nProvider } from './i18n'
import { theme } from './theme'
import '@mantine/core/styles.css'
import '@mantine/charts/styles.css'
import '@mantine/notifications/styles.css'
import './styles.css'

function Root() {
  return (
    <MantineProvider
      theme={theme}
      defaultColorScheme="auto"
    >
      <Notifications position="top-right" zIndex={2000} />
      <ErrorBoundary>
        <I18nProvider>
          <QueryClientProvider client={queryClient}>
            <App />
          </QueryClientProvider>
        </I18nProvider>
      </ErrorBoundary>
    </MantineProvider>
  )
}

// Apply the persisted color scheme before React mounts, replacing Mantine's
// <ColorSchemeScript>. That component emits an inline <script> which React 19
// hoists and executes, tripping our strict `script-src 'self'` CSP (no nonce,
// no 'unsafe-inline'). This runs from the same-origin bundle instead, so it
// prevents the flash of unstyled content without a CSP violation. The key and
// "auto" default mirror Mantine's localStorageColorSchemeManager defaults.
function applyInitialColorScheme() {
  try {
    const stored = window.localStorage.getItem('mantine-color-scheme-value')
    const scheme =
      stored === 'light' || stored === 'dark' || stored === 'auto' ? stored : 'auto'
    const computed =
      scheme !== 'auto'
        ? scheme
        : window.matchMedia('(prefers-color-scheme: dark)').matches
          ? 'dark'
          : 'light'
    document.documentElement.setAttribute('data-mantine-color-scheme', computed)
  } catch {
    // localStorage / matchMedia unavailable — MantineProvider applies it on mount.
  }
}

applyInitialColorScheme()

// The service worker used to keep GET /v1/config/export in this cache, and the
// copy outlived logout. The rule is gone, but Workbox only clears outdated
// precaches, so browsers that ran the old worker still hold the export until
// something deletes it.
if ('caches' in window) {
  void caches.delete('gateon-config-cache').catch(() => undefined)
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>,
)
