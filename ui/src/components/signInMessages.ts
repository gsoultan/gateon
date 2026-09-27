// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

/**
 * What the sign-in page says when a step is refused, keyed on the status the
 * gateway answered with. The server's own text is never shown: it is written
 * for logs and API clients, not for the person signing in, and an unexpected
 * failure's text can carry a database error.
 *
 * Sign-in answers a locked or disabled account with the same 401 as a wrong
 * password, so as not to say which accounts exist; the page does not guess.
 */

const LOCKED = "Too many failed attempts. The account is locked for a while; try again later.";

/** A refused username and password. */
export function signInRefusalMessage(status: number): string {
  switch (status) {
    case 401:
      return "Invalid username or password.";
    case 429:
      return "Too many sign-in attempts. Wait a minute and try again.";
    case 503:
      return "The gateway is not ready to sign you in yet. Try again shortly.";
    default:
      return "Sign-in failed. Please try again.";
  }
}

/** A refused two-factor code at sign-in. */
export function signInCodeRefusalMessage(status: number): string {
  switch (status) {
    case 401:
      return "That code is not valid. Check that your device's clock is correct and try again.";
    case 429:
      return LOCKED;
    default:
      return "The code could not be verified. Please try again.";
  }
}

/** A refused start of the two-factor enrolment an administrator required. */
export function enrolmentRefusalMessage(status: number): string {
  switch (status) {
    case 401:
      return "Invalid username or password.";
    case 403:
      return "This account cannot sign in. Contact an administrator.";
    case 429:
      return LOCKED;
    default:
      return "Two-factor setup could not be started. Please try again.";
  }
}
