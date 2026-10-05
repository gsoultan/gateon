// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

export interface MiddlewareTypeOption {
  label: string;
  value: string;
  group: string;
}

/**
 * The middleware types the Add Middleware picker offers: every type the
 * gateway's factory builds (internal/middleware/factory.go), each with an
 * editor in MiddlewareConfigEditor. scripts/checkconfig fails when the factory
 * builds a type this list does not offer. It used to be a literal in the page
 * that left out ten types the dashboard, the advisory and the posture told
 * operators to attach (truth T36 / NEW-8).
 */
export const MIDDLEWARE_TYPES: MiddlewareTypeOption[] = [
  { group: "Traffic", label: "Rate Limiting", value: "ratelimit" },
  { group: "Traffic", label: "In-Flight Requests (conn limit)", value: "inflightreq" },
  { group: "Traffic", label: "Buffering (max body)", value: "buffering" },
  { group: "Traffic", label: "Response Cache", value: "cache" },
  { group: "Traffic", label: "Compression", value: "compress" },
  { group: "Traffic", label: "Retry", value: "retry" },
  { group: "Traffic", label: "Circuit Breaker", value: "circuit_breaker" },

  { group: "Authentication", label: "Authentication", value: "auth" },
  { group: "Authentication", label: "Forward Auth", value: "forwardauth" },
  { group: "Authentication", label: "OpenID Connect Login", value: "oidc" },
  { group: "Authentication", label: "HMAC Signature", value: "hmac" },
  { group: "Authentication", label: "TLS Session Binding", value: "tls_binding" },
  { group: "Authentication", label: "Client Certificate Header (XFCC)", value: "xfcc" },

  { group: "Security", label: "WAF", value: "waf" },
  { group: "Security", label: "IP Filter", value: "ipfilter" },
  { group: "Security", label: "GeoIP", value: "geoip" },
  { group: "Security", label: "Bot Management", value: "bot_management" },
  { group: "Security", label: "Proof of Work Challenge", value: "pow" },
  { group: "Security", label: "Cloudflare Turnstile", value: "turnstile" },
  { group: "Security", label: "File Upload Security", value: "file_security" },
  { group: "Security", label: "Security Headers", value: "security_headers" },
  { group: "Security", label: "Access Policy (CEL)", value: "policy" },
  { group: "Security", label: "GraphQL Firewall", value: "graphql_firewall" },
  { group: "Security", label: "JSON Schema Validation", value: "schema_validation" },
  { group: "Security", label: "Honeypot", value: "honeypot" },
  { group: "Security", label: "Deception", value: "deception" },
  { group: "Security", label: "Tarpit", value: "tarpit" },
  { group: "Security", label: "Body Entropy", value: "entropy" },
  { group: "Security", label: "XSS Recognition", value: "xss_recognition" },
  { group: "Security", label: "SQL Injection Recognition", value: "sqli_recognition" },
  { group: "Security", label: "Threat Recognition", value: "threat_recognition" },

  { group: "Request & Response", label: "Header Manipulation", value: "headers" },
  { group: "Request & Response", label: "Forwarded Headers (X-Forwarded-Proto)", value: "forwardedheaders" },
  { group: "Request & Response", label: "Request ID", value: "request_id" },
  { group: "Request & Response", label: "Path Rewrite", value: "rewrite" },
  { group: "Request & Response", label: "Add Prefix", value: "addprefix" },
  { group: "Request & Response", label: "Strip Prefix", value: "stripprefix" },
  { group: "Request & Response", label: "Strip Prefix Regex", value: "stripprefixregex" },
  { group: "Request & Response", label: "Replace Path", value: "replacepath" },
  { group: "Request & Response", label: "Replace Path Regex", value: "replacepathregex" },
  { group: "Request & Response", label: "Body Transformation", value: "transform" },
  { group: "Request & Response", label: "CORS", value: "cors" },
  { group: "Request & Response", label: "gRPC-Web", value: "grpcweb" },
  { group: "Request & Response", label: "Custom Errors", value: "errors" },
  { group: "Request & Response", label: "WebAssembly (WASM)", value: "wasm" },

  { group: "Observability", label: "Access Logging", value: "accesslog" },
  { group: "Observability", label: "Prometheus Metrics", value: "metrics" },
];

/** MIDDLEWARE_TYPES grouped for a Mantine Select. */
export function middlewareTypeSelectData(): { group: string; items: { label: string; value: string }[] }[] {
  const groups = new Map<string, { label: string; value: string }[]>();
  for (const t of MIDDLEWARE_TYPES) {
    const items = groups.get(t.group) ?? [];
    items.push({ label: t.label, value: t.value });
    groups.set(t.group, items);
  }
  return [...groups].map(([group, items]) => ({ group, items }));
}
