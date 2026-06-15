import type { ErrorComponentProps } from "@tanstack/react-router";
import { useRouter } from "@tanstack/react-router";
import { ErrorFallback } from "./ErrorFallback";

function newErrorId(): string {
  return Math.random().toString(36).slice(2, 10).toUpperCase();
}

/**
 * RouteErrorComponent is wired into TanStack Router as the per-route
 * `errorComponent`. It isolates a failed route to its own fallback so the rest
 * of the shell (navigation) stays usable, and lets the user retry by
 * invalidating the router.
 */
export function RouteErrorComponent({ error, reset }: ErrorComponentProps) {
  const router = useRouter();
  return (
    <ErrorFallback
      error={error}
      errorId={newErrorId()}
      onReset={() => {
        reset();
        router.invalidate();
      }}
    />
  );
}
