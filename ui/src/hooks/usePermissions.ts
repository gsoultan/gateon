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

    return {
      canWrite,
      canManageUsers,
      canEditGlobal,
      canImportConfig,
      canExportConfig,
      canUploadCerts,
      isViewer,
    };
  }, [user?.role]);
}
