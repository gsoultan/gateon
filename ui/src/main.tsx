import React from 'react'
import ReactDOM from 'react-dom/client'
import { MantineProvider, createTheme, virtualColor, ColorSchemeScript } from '@mantine/core'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Notifications } from '@mantine/notifications'
import App from './App'
import { useThemeStore } from './store/useThemeStore'
import '@mantine/core/styles.css'
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
  primaryColor: 'indigo',
  primaryShade: { light: 6, dark: 7 },
  fontFamily: 'Inter, system-ui, -apple-system, sans-serif',
  fontFamilyMonospace: 'JetBrains Mono, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
  headings: {
    fontFamily: 'Inter, system-ui, -apple-system, sans-serif',
    fontWeight: '700',
  },
  defaultRadius: 'lg',
  white: '#fff',
  black: '#0a0a0b',
  colors: {
    dark: [
      '#C1C2C5',
      '#A6A7AB',
      '#909296',
      '#5c5f66',
      '#373A40',
      '#2C2E33',
      '#1e1f23',
      '#141517',
      '#0c0d0e',
      '#050505',
    ],
  },
  components: {
    Card: {
      defaultProps: {
        radius: 'lg',
        withBorder: true,
        shadow: 'sm',
      },
      styles: {
        root: {
          transition: 'transform 200ms ease, box-shadow 200ms ease',
        }
      }
    },
    Button: {
      defaultProps: {
        radius: 'md',
        loaderProps: { type: 'bars' },
      },
      styles: {
        root: {
          transition: 'background-color 200ms ease, transform 100ms ease',
          '&:active': {
            transform: 'scale(0.98)',
          }
        }
      }
    },
    TextInput: {
      defaultProps: {
        radius: 'md',
        size: 'md',
      },
    },
    Select: {
      defaultProps: {
        radius: 'md',
        size: 'md',
      },
    },
    NumberInput: {
      defaultProps: {
        radius: 'md',
        size: 'md',
      }
    },
    Badge: {
      defaultProps: {
        radius: 'md',
        variant: 'light',
      }
    }
  },
})

function Root() {
  const colorScheme = useThemeStore((state) => state.colorScheme)

  return (
    <QueryClientProvider client={queryClient}>
      <MantineProvider theme={theme} defaultColorScheme={colorScheme}>
        <Notifications position="top-right" zIndex={2000} />
        <App />
      </MantineProvider>
    </QueryClientProvider>
  )
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ColorSchemeScript defaultColorScheme="dark" />
    <Root />
  </React.StrictMode>,
)
