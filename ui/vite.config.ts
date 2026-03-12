import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          'mantine-vendor': ['@mantine/core', '@mantine/hooks', '@mantine/notifications'],
          'tabler-icons': ['@tabler/icons-react'],
          'react-vendor': ['react', 'react-dom'],
          'tanstack-vendor': ['@tanstack/react-router', '@tanstack/react-query', '@tanstack/react-form'],
        },
      },
    },
    chunkSizeWarningLimit: 1000,
  },
})
