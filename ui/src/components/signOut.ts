// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

/**
 * What signing out does, said wherever the dashboard offers it: the header's
 * profile menu, the Profile page and the command palette.
 *
 * The gateway ends every session of the account, not only this browser's. A
 * session is a bearer token, and the only way to end a copy of one -- which is
 * why someone signs out of a device they no longer trust -- is to end them
 * all, so the other devices signed in to the account are signed out too.
 */
export const SIGN_OUT_SCOPE = "Ends every session of this account, on every device";
