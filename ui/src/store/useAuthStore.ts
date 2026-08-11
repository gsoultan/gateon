// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { User } from "../types/gateon";

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
    },
  ),
);
