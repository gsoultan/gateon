// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useMemo } from "react";
import { useAuthStore } from "../store/useAuthStore";

/** RBAC permissions: admin=full; operator=read+write config (no users/global); viewer=read only. */
export function usePermissions() {
  const user = useAuthStore((s) => s.user);

  return useMemo(() => {
    const role = user?.role;
    const canWrite =
      role === "admin" || role === "operator";
    const canManageUsers = role === "admin";
    const canEditGlobal = role === "admin" || role === "operator";
    const canImportConfig = canWrite;
    const canExportConfig = true; // all authenticated can export (read)
    const canUploadCerts = role === "admin" || role === "operator";
    const isViewer = role === "viewer";
    // The global settings that decide who can reach and sign in to the
    // management plane, whom the gateway trusts, and what is recorded: the
    // gateway refuses an operator's change to any of them (ADR 0040).
    const canChangeSecurityBoundary = role === "admin";

    return {
      canWrite,
      canManageUsers,
      canEditGlobal,
      canImportConfig,
      canExportConfig,
      canUploadCerts,
      isViewer,
      canChangeSecurityBoundary,
    };
  }, [user?.role]);
}

/** Why an administrator-only global setting is read-only for an operator. */
export const ADMIN_ONLY_REASON =
  "Only an administrator can change this: it decides who can reach or sign in to the management plane, " +
  "whom the gateway trusts, or what is recorded.";

/**
 * For a control that edits an administrator-only global setting (ADR 0040):
 * `disabled` is the control's own disabled state, also set for anyone who is
 * not an administrator, and `locked` is true for a caller who may edit the
 * other settings but not this one -- the case that needs saying why.
 */
export function useAdminOnlySetting(disabled: boolean) {
  const role = useAuthStore((s) => s.user?.role);
  const admin = role === "admin";
  const mayEditGlobal = admin || role === "operator";
  return {
    disabled: disabled || !admin,
    locked: mayEditGlobal && !admin,
  };
}
