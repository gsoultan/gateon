// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useEffect } from "react";
import { useUrlFilters } from "../../hooks/useUrlFilters";

/** The search a link sets to open a page with its create form showing. */
export const CREATE_SEARCH = { new: "1" } as const;

/** Whether a page was opened by a link asking for its create form. */
export function wantsCreateForm(search: Record<string, unknown>): boolean {
  // The router parses "?new=1" to the number 1.
  return search.new === "1" || search.new === 1;
}

/**
 * Opens a page's create form when a link asked for it, then drops the request
 * from the URL so a reload or a back-navigation does not open it again. The
 * dashboard's "Add route" and "Add service" used to land on the list and
 * leave the operator to find the button. A caller that cannot create gets the
 * list, as before.
 */
export function useCreateFromLink(canCreate: boolean, openCreate: () => void) {
  const [search, setSearch] = useUrlFilters<{ new: string }>();
  const requested = wantsCreateForm(search);
  useEffect(() => {
    if (!requested) return;
    if (canCreate) openCreate();
    setSearch({ new: undefined });
  }, [requested, canCreate, openCreate, setSearch]);
}
