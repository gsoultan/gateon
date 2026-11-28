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

// ADR 0108: what the AI agent policy does on a route.
export const AI_AGENTS_HELP =
  "For clients whose User-Agent names an AI crawler or agent (GPTBot, ClaudeBot, PerplexityBot and others). " +
  "Verify admits a client at an address its vendor publishes, past the JavaScript challenge it cannot run, and " +
  "refuses one that names an agent from any other address. The vendor lists are set in Settings, Security, Bot " +
  "Management; an agent with no list loaded meets this route's other checks. Maze verifies the same way, but " +
  "answers a fake with generated pages of links that lead only to more of them, so a scraper spends its crawl on " +
  "nothing of the site's. Refuse turns every AI agent away.";
export const AI_AGENT_POLICY_OPTIONS = [
  { value: "off", label: "Off: treat like any other client" },
  { value: "verify", label: "Verify against the vendor's addresses" },
  { value: "maze", label: "Verify, and send fakes into a maze" },
  { value: "refuse", label: "Refuse every AI agent" },
];

// The agents the gateway recognises (internal/security/aiagent catalog.go);
// the gateway refuses a list for any other name at save.
export const AI_AGENT_NAMES = [
  "GPTBot", "OAI-SearchBot", "ChatGPT-User",
  "ClaudeBot", "Claude-SearchBot", "Claude-User",
  "PerplexityBot", "Perplexity-User",
  "CCBot", "Bytespider", "Amazonbot", "meta-externalagent",
];
export const AI_AGENT_RANGES_HELP =
  "Where each AI agent's vendor publishes the addresses it crawls from: a JSON list in the shape OpenAI and " +
  "Perplexity publish, or one address or CIDR per line. Gateon fetches each list in the background every 12 " +
  "hours and keeps the last good copy if a fetch fails. Only https:// is accepted. Routes use these lists only " +
  "when their Bot Management is set to verify AI agents. Administrators only.";
