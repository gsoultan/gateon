// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Code, ConnectError, type Interceptor } from "@connectrpc/connect";
import { useAuthStore } from "../store/useAuthStore";

// endSessionOnUnauthenticated does for the generated client what apiFetch does
// for REST: a call the gateway refuses for want of a session -- expired or
// revoked, answered 401 before RBAC runs -- signs the dashboard out, instead of
// leaving every page that moved to this client failing in place. A permission
// refusal is PermissionDenied and leaves the session alone.
export const endSessionOnUnauthenticated: Interceptor = (next) => async (req) => {
  try {
    return await next(req);
  } catch (err) {
    if (err instanceof ConnectError && err.code === Code.Unauthenticated) {
      useAuthStore.getState().logout();
    }
    throw err;
  }
};

// withSessionCookie sends the session cookie on every call, as apiFetch does:
// the dashboard may be served from another origin than the API it manages, and
// fetch's default sends cookies only to its own.
// Object.assign carries over fetch's own properties, so this is a fetch by type
// as well as by behaviour without a cast.
export const withSessionCookie: typeof globalThis.fetch = Object.assign(
  (input: RequestInfo | URL, init?: RequestInit) => globalThis.fetch(input, { ...init, credentials: "include" }),
  globalThis.fetch,
);
