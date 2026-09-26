// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { visualizer } from 'rollup-plugin-visualizer'
import { compression } from 'vite-plugin-compression2'
import { VitePWA } from 'vite-plugin-pwa'

// Set ANALYZE=1 to emit dist/stats.html (treemap of chunk/module sizes) after a
// build, e.g. `ANALYZE=1 bun run build`. Off by default so normal/CI builds are
// unaffected.
const analyze = process.env.ANALYZE === '1' || process.env.ANALYZE === 'true'

export default defineConfig({
  plugins: [
    react(),
    // Pre-compress assets to save CPU at runtime
    compression({ algorithm: 'brotli', exclude: [/\.(br)$/, /\.(gz)$/] }),
    compression({ algorithm: 'gzip', exclude: [/\.(br)$/, /\.(gz)$/] }),
    // PWA: Offline-first assets and near-instant loading
    VitePWA({
      registerType: 'autoUpdate',
      includeAssets: ['favicon.ico', 'apple-touch-icon.png', 'mask-icon.svg'],
      manifest: {
        name: 'Gateon Dashboard',
        short_name: 'Gateon',
        description: 'Ultra-Intelligent Defense Gateway',
        theme_color: '#1a1b1e',
        icons: [
          {
            src: 'pwa-192x192.png',
            sizes: '192x192',
            type: 'image/png'
          },
          {
            src: 'pwa-512x512.png',
            sizes: '512x512',
            type: 'image/png'
          }
        ]
      },
      // The worker is scoped to "/" on the management origin, which also serves
      // the API, /healthz, Prometheus' /metrics and any proxied application a
      // route shadows onto the management entrypoint. What it answers from its
      // own cache never reaches the server, so it caches hashed static assets
      // and nothing else:
      //
      // - No API responses. A stale-while-revalidate rule over /v1/config* only
      //   ever matched the config export, so a backup taken after a change was
      //   the previous export, and the full configuration, credentials
      //   included, stayed readable from the page after logout.
      // - No HTML and no navigation fallback. The fallback answered every page
      //   load on the origin with its install-time index.html — /healthz
      //   rendered the dashboard — and that copy carried one CSP nonce that
      //   every page load then reused. The server already answers unknown paths
      //   with the dashboard, with a fresh nonce each time.
      workbox: {
        globPatterns: ['**/*.{js,css,ico,png,svg,woff2}'],
        navigateFallback: null,
      }
    }),
    ...(analyze
      ? [
          visualizer({
            filename: 'dist/stats.html',
            template: 'treemap',
            gzipSize: true,
            brotliSize: true,
          }),
        ]
      : []),
  ],
  resolve: {
    dedupe: ['@tanstack/react-query', 'react', 'react-dom'],
  },
  server: {
    port: 5173,
  },
  build: {
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [
            {
              test: /[\\/]node_modules[\\/]@mantine[\\/](core|hooks|notifications)[\\/]/,
              name: 'mantine-vendor',
            },
            {
              test: /[\\/]node_modules[\\/]@tabler[\\/]icons-react[\\/]/,
              name: 'tabler-icons',
            },
            {
              test: /[\\/]node_modules[\\/]react(-dom)?[\\/]/,
              name: 'react-vendor',
            },
            {
              test: /[\\/]node_modules[\\/]@tanstack[\\/](react-router|react-query|react-form)[\\/]/,
              name: 'tanstack-vendor',
            },
            {
              // Heavy graph/map libraries: isolate into their own chunks so they
              // are fetched only on the (lazy) Topology and Diagnostics routes.
              test: /[\\/]node_modules[\\/](@xyflow[\\/]react|dagre|leaflet|react-leaflet)[\\/]/,
              name: 'viz-vendor',
            },
          ],
        },
      },
    },
    chunkSizeWarningLimit: 500,
  },
})
