import { QueryClient, MutationCache, keepPreviousData } from '@tanstack/react-query'
import { notifyError } from './utils/notify'

/**
 * Global query client.
 *
 * - staleTime/gcTime avoid refetch flicker when revisiting cached pages.
 * - keepPreviousData keeps paginated/time-window tables populated while refetching.
 * - A global MutationCache surfaces a consistent error toast for any mutation that
 *   does not handle errors itself. Mutations with their own onError (or
 *   meta.skipGlobalError) are left untouched to avoid duplicate toasts.
 */
export const queryClient = new QueryClient({
  mutationCache: new MutationCache({
    onError: (error, _vars, _ctx, mutation) => {
      if (mutation.options.onError) return
      if (mutation.meta?.skipGlobalError) return
      notifyError(error)
    },
  }),
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 30_000,
      gcTime: 5 * 60_000,
      placeholderData: keepPreviousData,
    },
  },
})
