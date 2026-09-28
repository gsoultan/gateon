// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { User } from "../types/gateon";

/** What a save may change: any field of the account, and a new password. */
export type UserChanges = Partial<Omit<User, "id">>;

/**
 * The body of a save to PUT /v1/users for an account that exists: the changes,
 * over everything else the account has now.
 *
 * The gateway writes an account's disabled flag and its pending-2FA
 * requirement from every save, so a save that leaves them out clears them.
 * The Edit form sent only the name, the password field and the role: changing
 * a disabled account's role enabled it again, and changing the role of an
 * account required to set up 2FA dropped the requirement. The 2FA enrolment
 * itself is sent so the gateway can tell an enrolled account, whose pending
 * flag it leaves alone.
 */
export function userUpdateBody(user: User, changes: UserChanges): Record<string, unknown> {
  return {
    id: user.id,
    username: user.username,
    role: user.role,
    disabled: user.disabled ?? false,
    twoFactorPending: user.twoFactorPending ?? false,
    twoFactorEnabled: user.twoFactorEnabled ?? false,
    ...changes,
  };
}
