import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
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
          ],
        },
      },
    },
    chunkSizeWarningLimit: 1000,
  },
})
