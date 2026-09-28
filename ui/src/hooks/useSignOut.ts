// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useCallback } from "react";
import { useNavigate } from "@tanstack/react-router";
import { notifications } from "@mantine/notifications";
import { useAuthStore } from "../store/useAuthStore";
import { queryClient } from "../queryClient";
import { signOutEverywhere } from "../components/signOut";
import { notifyError } from "../utils/notify";

/**
 * The one sign-out behind every control that offers it: the header's profile
 * menu, the Profile page and the command palette. It resolves to whether this
 * browser is signed out, so a control showing progress can stop when it is not.
 *
 * Signed out, it leaves for the sign-in page, telling the user when the
 * account's other sessions may still be signed in. Not signed out, it stays,
 * so the user can try again.
 */
export function useSignOut(): () => Promise<boolean> {
  const logout = useAuthStore((state) => state.logout);
  const navigate = useNavigate();
  return useCallback(async () => {
    const outcome = await signOutEverywhere();
    if (!outcome.signedOut) {
      notifyError(null, { title: "Could not sign out", message: outcome.warning });
      return false;
    }
    // Drop cached, potentially sensitive data from this session.
    queryClient.clear();
    logout();
    void navigate({ to: "/login" });
    if (outcome.warning) {
      notifications.show({
        title: "Other sessions may still be signed in",
        message: outcome.warning,
        color: "orange",
        withBorder: true,
        autoClose: false,
      });
    }
    return true;
  }, [logout, navigate]);
}
