// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// What the bot-management checks prove, in the words ADR 0045 settles on. The
// global defaults (BotManagementSection) show the same text.
export const BROWSER_HEADER_CHECK_HELP =
  "Refuses requests with no User-Agent, and requests whose User-Agent claims Chrome, Edge, Firefox or Safari " +
  "but that carry none of the Sec-Fetch headers those browsers send. Clients that do not claim to be a browser " +
  "(curl, SDKs, crawlers) are not checked.";
export const JS_CHALLENGE_HELP =
  "Before a client reaches the backend it must run a short calculation in JavaScript (about a second) and keep " +
  "the cookie it earns, bound to its address and browser. Clients that cannot run JavaScript, such as curl, API " +
  "clients and most uptime monitors, are refused on this route. It raises the cost of automated traffic; it does " +
  "not prove a visitor is human.";
