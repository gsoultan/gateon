// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

/**
 * The dashboard's words for the API's names. Traefik vocabulary (EntryPoints,
 * Middlewares, Client Authorities, TLS Options) only developers know gets the
 * plain word; the API keeps its names.
 */
export const TERMS = {
  listener: { word: "Listener", plural: "Listeners", api: "entryPoint" },
  policy: { word: "Policy", plural: "Policies", api: "middleware" },
  service: { word: "Service", plural: "Services", api: "service" },
  clientCa: { word: "Client CA", plural: "Client CAs", api: "clientAuthority" },
  tlsProfile: { word: "TLS profile", plural: "TLS profiles", api: "tlsOption" },
  match: { word: "Match", plural: "Matches", api: "rule" },
} as const;

export type TermKey = keyof typeof TERMS;
