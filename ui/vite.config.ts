import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { visualizer } from 'rollup-plugin-visualizer'

// Set ANALYZE=1 to emit dist/stats.html (treemap of chunk/module sizes) after a
// build, e.g. `ANALYZE=1 bun run build`. Off by default so normal/CI builds are
// unaffected.
const analyze = process.env.ANALYZE === '1' || process.env.ANALYZE === 'true'

export default defineConfig({
  plugins: [
    react(),
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
