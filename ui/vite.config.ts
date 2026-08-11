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
      workbox: {
        globPatterns: ['**/*.{js,css,html,ico,png,svg,woff2}'],
        // Stale-While-Revalidate for configuration files ensures immediate transition
        // without loading spinners, while keeping the data fresh in the background.
        runtimeCaching: [
          {
            urlPattern: /\/v1\/config.*/i,
            handler: 'StaleWhileRevalidate',
            options: {
              cacheName: 'gateon-config-cache',
              expiration: {
                maxEntries: 50,
                maxAgeSeconds: 60 * 60 * 24 // 24 hours
              }
            }
          }
        ]
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
