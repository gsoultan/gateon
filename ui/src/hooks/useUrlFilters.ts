import { useNavigate, useSearch } from "@tanstack/react-router";
import { useCallback } from "react";

/**
 * A filter value persisted in the URL. We intentionally keep it to the small
 * set of primitives that round-trip cleanly through query-string state.
 */
type FilterValue = string | number | boolean | null | undefined;

/**
 * useUrlFilters lifts a page's filter/search state into the URL's search
 * params so that a filtered view is bookmarkable and shareable. Reads come from
 * the (validated) route search; writes merge into the existing search and prune
 * empty values so the URL stays clean. Navigation uses `replace` to avoid
 * polluting the browser history while the user types.
 *
 * @returns a tuple of the current (partial) filters and a setter that merges
 *          partial updates.
 */
export function useUrlFilters<T extends Record<string, FilterValue>>(): readonly [
  Partial<T>,
  (updates: Partial<T>) => void,
] {
  // strict:false lets this hook work on any route without coupling to a route id.
  const search = useSearch({ strict: false }) as Partial<T>;
  const navigate = useNavigate();

  const setFilters = useCallback(
    (updates: Partial<T>) => {
      navigate({
        to: ".",
        search: (prev: Record<string, unknown>) => {
          const next: Record<string, unknown> = { ...prev, ...updates };
          for (const key of Object.keys(next)) {
            const value = next[key];
            if (value === "" || value === null || value === undefined) {
              delete next[key];
            }
          }
          return next;
        },
        replace: true,
      });
    },
    [navigate],
  );

  return [search, setFilters] as const;
}

/** Reads a string search param defensively (used by `validateSearch`). */
export function asSearchString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}
