import React from 'react'
import ReactDOM from 'react-dom/client'
import { MantineProvider, createTheme, virtualColor, ColorSchemeScript } from '@mantine/core'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Notifications } from '@mantine/notifications'
import App from './App'
import '@mantine/core/styles.css'
import '@mantine/charts/styles.css'
import '@mantine/notifications/styles.css'
import './styles.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})

const theme = createTheme({
  primaryColor: 'brand',
  primaryShade: { light: 6, dark: 8 },
  fontFamily: 'Inter, system-ui, -apple-system, sans-serif',
  fontFamilyMonospace: 'JetBrains Mono, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
  headings: {
    fontFamily: 'Inter, system-ui, -apple-system, sans-serif',
    fontWeight: '800',
  },
  defaultRadius: 'md',
  white: '#fff',
  black: '#0a0a0b',
  colors: {
    brand: [
      '#e5f2ff',
      '#cce5ff',
      '#99caff',
      '#66afff',
      '#3394ff',
      '#0073ea', // Primary Monday.com blue
      '#0066d1',
      '#0059b8',
      '#004c9e',
      '#003f85',
    ],
    dark: [
      '#d5d7e0',
      '#acaebf',
      '#8c8fa3',
      '#666980',
      '#4d4f66',
      '#34354a',
      '#2b2c3d',
      '#1d1e30',
      '#0c0d21',
      '#01010a',
    ],
  },
  components: {
    Card: {
      defaultProps: {
        radius: 'md',
        withBorder: true,
        shadow: 'xs',
      },
      styles: {
        root: {
          transition: 'transform 200ms ease, box-shadow 200ms ease',
          backgroundColor: 'var(--mantine-color-body)',
        }
      }
    },
    Button: {
      defaultProps: {
        radius: 'md',
        loaderProps: { type: 'bars' },
        fw: 600,
      },
      styles: {
        root: {
          transition: 'background-color 200ms ease, transform 100ms ease',
          fontWeight: 600,
          '&:active': {
            transform: 'scale(0.98)',
          }
        }
      }
    },
    Paper: {
      defaultProps: {
        radius: "md",
        withBorder: true,
      },
    },
    TextInput: {
      defaultProps: {
        radius: 'sm',
        size: 'sm',
      },
    },
    Select: {
      defaultProps: {
        radius: 'sm',
        size: 'sm',
      },
    },
    NumberInput: {
      defaultProps: {
        radius: 'sm',
        size: 'sm',
      }
    },
    Badge: {
      defaultProps: {
        radius: 'sm',
        variant: 'light',
        fw: 700,
      }
    },
    NavLink: {
      styles: {
        root: {
          borderRadius: 'var(--mantine-radius-sm)',
          transition: 'all 150ms ease',
        },
      }
    }
  },
  shadows: {
    xs: '0 1px 2px rgba(0, 0, 0, 0.05)',
    sm: '0 1px 3px rgba(0, 0, 0, 0.1), 0 1px 2px rgba(0, 0, 0, 0.06)',
    md: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
    lg: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
    xl: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
  },
})

function Root() {
  return (
    <MantineProvider
      theme={theme}
      defaultColorScheme="auto"
      storageKey="gateon-color-scheme"
    >
      <Notifications position="top-right" zIndex={2000} />
      <App />
    </MantineProvider>
  )
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <ColorSchemeScript
        defaultColorScheme="auto"
        storageKey="gateon-color-scheme"
      />
      <Root />
    </QueryClientProvider>
  </React.StrictMode>,
)
