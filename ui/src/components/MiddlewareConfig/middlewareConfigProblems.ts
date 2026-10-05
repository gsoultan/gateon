// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { isSecretReference, isStoredSecret } from "../../utils/storedSecret";
import { authConfigProblem } from "./authConfigProblems";

/**
 * What a middleware form must not save, said the way the gateway refuses it
 * (ADR 0043, ADR 0046). The gateway refuses the same configs on every
 * transport; the form says so before the round trip, and keeps Save disabled.
 */

const splitList = (v: string | undefined) =>
  (v || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

export const WILDCARD_CREDENTIALS =
  'Allow Credentials needs named origins: browsers refuse a credentialed response that allows every origin ("*"). ' +
  "List the origins that send cookies or an Authorization header, or turn Allow Credentials off.";

/** Why a cors or grpcweb config cannot be saved, or undefined. */
export function corsProblem(config: Record<string, string>): string | undefined {
  if ((config.preset || "").toLowerCase() === "backend") return undefined;
  if (config.allow_credentials !== "true") return undefined;
  return splitList(config.allowed_origins).includes("*") ? WILDCARD_CREDENTIALS : undefined;
}

export const XFCC_BY_REQUIRED =
  "Forward By needs the URI this gateway forwards as By= (the URI SAN of its certificate), e.g. spiffe://example.org/gateway.";

/** Whether v is an absolute URI, the form By= takes. */
function isAbsoluteURI(v: string): boolean {
  return /^[a-zA-Z][a-zA-Z0-9+.-]*:\S+$/.test(v.trim());
}

/** Why an xfcc config cannot be saved, or undefined. */
export function xfccProblem(config: Record<string, string>): string | undefined {
  if (config.forward_by !== "true") return undefined;
  return isAbsoluteURI(config.by || "") ? undefined : XFCC_BY_REQUIRED;
}

export const TLS_BINDING_SECRET_REQUIRED =
  "Enter a secret of at least 32 characters. The binding is an HMAC under it, and every gateway serving the route must share it.";

/** Why a tls_binding config cannot be saved, or undefined. */
export function tlsBindingProblem(config: Record<string, string>): string | undefined {
  const secret = config.secret || "";
  // A stored secret comes back as the placeholder, and is kept; a reference
  // is resolved and checked by the gateway.
  if (isStoredSecret(secret) || isSecretReference(secret)) return undefined;
  return secret.length >= 32 ? undefined : TLS_BINDING_SECRET_REQUIRED;
}

/**
 * Why a tarpit config cannot be saved, or undefined. The factory reads an
 * unset threshold as 0, and the delay is the base delay scaled by the score
 * over the threshold: at 0 every client, a clean one included, meets it and
 * the delay is a division by zero.
 */
export function tarpitProblem(config: Record<string, string>): string | undefined {
  const t = Number(config.threshold);
  if (!config.threshold || !Number.isFinite(t) || t <= 0) {
    return "Set a threat score threshold above 0: at 0 every client is delayed.";
  }
  if (!config.max_delay) return "Set a maximum delay, so no request is held indefinitely.";
  return undefined;
}

export const ENTROPY_THRESHOLD_RANGE =
  "Set an entropy threshold above 0 and at most 8 bits per byte, or leave it empty for 7.5: " +
  "at 0 every request body is recorded as a threat, and no body measures above 8.";

/**
 * Why a body-entropy config cannot be saved, or undefined. Empty is the
 * gateway's default of 7.5; the gateway refuses the same out-of-range values.
 */
export function entropyProblem(config: Record<string, string>): string | undefined {
  const raw = (config.threshold || "").trim();
  if (!raw) return undefined;
  const t = Number(raw);
  if (Number.isNaN(t)) return undefined; // not a number: the gateway names the parse error
  return t > 0 && t <= 8 ? undefined : ENTROPY_THRESHOLD_RANGE;
}

/** The first reason a middleware of this type cannot be saved, or undefined. */
export function middlewareConfigProblem(type: string, config: Record<string, string>): string | undefined {
  switch (type) {
    case "auth":
      return authConfigProblem(config);
    case "cors":
    case "grpcweb":
      return corsProblem(config);
    case "xfcc":
      return xfccProblem(config);
    case "tls_binding":
      return tlsBindingProblem(config);
    case "tarpit":
      return tarpitProblem(config);
    case "entropy":
      return entropyProblem(config);
    default:
      return undefined;
  }
}

/**
 * Keys the gateway no longer reads. "Trust Cloudflare Headers" on a rate
 * limit, IP filter or GeoIP middleware never changed which client address it
 * saw -- the entrypoint resolves it once, under the global setting -- and a
 * saved value that disagrees with that setting is refused. The form drops the
 * key on save, so a middleware saved before keeps saving.
 */
const RETIRED_KEYS: Record<string, string[]> = {
  ratelimit: ["trust_cloudflare_headers"],
  ipfilter: ["trust_cloudflare_headers"],
  geoip: ["trust_cloudflare_headers"],
};

/** config without the keys this middleware type no longer reads. */
export function withoutRetiredKeys(type: string, config: Record<string, string>): Record<string, string> {
  const retired = RETIRED_KEYS[type];
  if (!retired) return config;
  const out = { ...config };
  for (const k of retired) delete out[k];
  return out;
}
