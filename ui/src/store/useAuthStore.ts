// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { User } from "../types/gateon";

/**
 * Sentinel stored in place of a real token when the session lives in the
 * HttpOnly `gateon_session` cookie — which is now the only way a session is
 * held. Call sites treat it as "authenticated, but there is no token for you
 * to read", and the browser attaches the cookie itself.
 */
export const COOKIE_SESSION = "__cookie__";

interface AuthState {
  token: string | null;
  user: User | null;
  setAuth: (token: string, user: User) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      user: null,
      setAuth: (token, user) => set({ token, user }),
      logout: () => {
        // Close the event stream before dropping the credentials it was opened
        // with. Otherwise it stays open, fails on the next event, and then
        // reconnects on a schedule against a session that no longer exists —
        // knocking on the gateway indefinitely after the user has left.
        //
        // Imported lazily: the auth store is created during module init and a
        // top-level import would make these two stores construct each other.
        void import("./useRealTimeStore").then((m) => m.useRealTimeStore.getState().disconnect());
        set({ token: null, user: null });
      },
    }),
    {
      name: "gateon-auth",
      // Persist the user, never the token.
      //
      // The session token used to be written to localStorage, which is
      // readable by any script running on this origin. This dashboard renders
      // traffic captured from hostile clients, so a single stored-XSS bug
      // anywhere in it would have handed an attacker a working administrator
      // token — the highest-value credential the product has. The token now
      // lives only in the HttpOnly `gateon_session` cookie, which script
      // cannot read at all.
      //
      // The user object is kept so a refresh can paint the shell (name, role)
      // without a round trip. It is display data, not a credential: the server
      // re-derives the real identity from the cookie on every request, so a
      // tampered copy here grants nothing.
      partialize: (state) => ({ user: state.user }),
    },
  ),
);
