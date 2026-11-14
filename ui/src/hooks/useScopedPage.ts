// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useState } from "react";

/** A page number and the filters it was chosen under. */
export interface ScopedPage {
  scope: string;
  page: number;
}

/**
 * The page to show for the filters in scope: the one chosen under these
 * filters, or the first page once they change.
 *
 * The Threats and Blocks lists reset their page with an effect that listed some
 * filters and not others. Switching Blocks between user and IP mitigations kept
 * the page, so page 3 of one list opened an empty "No threats found" page of a
 * list with two; and even where it did reset, the first render asked the server
 * for the old page of the new filter before the effect ran.
 */
export function pageInScope(state: ScopedPage, scope: string): number {
  return state.scope === scope ? state.page : 1;
}

/** useState for a page number that returns to 1 whenever scope changes. */
export function useScopedPage(scope: string): [number, (page: number) => void] {
  const [state, setState] = useState<ScopedPage>({ scope, page: 1 });
  return [pageInScope(state, scope), (page: number) => setState({ scope, page })];
}
