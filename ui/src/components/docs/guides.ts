// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import readmeContent from "../../../docs/README.md?raw";
import managementEntrypointContent from "../../../docs/management-entrypoint.md?raw";
import proxyProtocolContent from "../../../docs/proxy-protocol.md?raw";
import emailBackendContent from "../../../docs/email-backend-setup.md?raw";
import servicesContent from "../../../docs/services.md?raw";
import websocketsContent from "../../../docs/websockets-sse.md?raw";

export interface Guide {
  id: string;
  label: string;
  file: string;
  content: string;
}

/**
 * GUIDES are the bundled markdown guides (ui/docs), one tab each, in the order
 * the tabs appear. Every guide the Introduction's index lists has a tab: two
 * of them (management-entrypoint.md, websockets-sse.md) used to have none.
 */
export const GUIDES: Guide[] = [
  { id: "intro", label: "Introduction", file: "README.md", content: readmeContent },
  { id: "management-entrypoint", label: "Management Entrypoint", file: "management-entrypoint.md", content: managementEntrypointContent },
  { id: "proxy-protocol", label: "Proxy Protocol", file: "proxy-protocol.md", content: proxyProtocolContent },
  { id: "email-backend", label: "Email Backend (SMTP, IMAP, POP3)", file: "email-backend-setup.md", content: emailBackendContent },
  { id: "running-service", label: "Running as a Service", file: "services.md", content: servicesContent },
  { id: "websockets-sse", label: "WebSockets & SSE", file: "websockets-sse.md", content: websocketsContent },
];

/**
 * guideIdForHref names the tab a link to another guide should open, or
 * undefined when href is not one. The guides link to each other as files
 * ("./services.md"), which the gateway does not serve: followed as links they
 * opened a window reading "Not Found".
 */
export function guideIdForHref(href: string | undefined): string | undefined {
  if (!href || isExternalHref(href)) return undefined;
  const file = href.split("#")[0].replace(/^\.\//, "");
  return GUIDES.find((g) => g.file === file)?.id;
}

/** isExternalHref reports whether href leaves the dashboard for another site. */
export function isExternalHref(href: string | undefined): boolean {
  return !!href && /^https?:\/\//i.test(href);
}
