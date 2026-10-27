// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

export const POLICY_FAMILIES = ["Limits", "Access", "Protection", "Headers and paths", "Traffic shaping", "Observability"] as const;
export type PolicyFamily = (typeof POLICY_FAMILIES)[number];

/** What each family of policy is for, in the words of the catalog. */
export const POLICY_FAMILY_DESCRIPTIONS: Record<PolicyFamily, string> = {
  Limits: "How much a client may send: requests, connections, body size, and when to stop trying a failing backend.",
  Access: "Who may reach the route: credentials, client certificates, addresses and countries.",
  Protection: "What is refused as an attack: the WAF, bots, uploads, injection and the traps for scanners.",
  "Headers and paths": "What the request and response look like on the way through: headers, prefixes, rewrites, CORS and error pages.",
  "Traffic shaping": "What happens to the body: caching, compression, retries and custom transforms.",
  Observability: "What is recorded about the route.",
};

export interface MiddlewareTypeOption {
  label: string;
  value: string;
  group: PolicyFamily;
  /** One line on what the policy does, for the catalog. */
  description: string;
}

/**
 * The policy types the Add policy catalog offers: every type the gateway's
 * factory builds (internal/middleware/factory.go), each with an editor in
 * MiddlewareConfigEditor. scripts/checkconfig fails when the factory builds a
 * type this list does not offer. It used to be a literal in the page that left
 * out ten types the dashboard, the advisory and the posture told operators to
 * attach (truth T36 / NEW-8). The six families are the catalog's shelves; the
 * `type` value is unchanged and is what the API and config name.
 */
export const MIDDLEWARE_TYPES: MiddlewareTypeOption[] = [
  { group: "Limits", label: "Rate limit", value: "ratelimit", description: "Cap requests per minute per client, tenant or fingerprint." },
  { group: "Limits", label: "In-flight requests", value: "inflightreq", description: "Cap the requests a client may have open at once." },
  { group: "Limits", label: "Body size", value: "buffering", description: "Refuse a request body above a size." },
  { group: "Limits", label: "Circuit breaker", value: "circuit_breaker", description: "Stop sending to a backend that keeps failing, and probe it to recover." },

  { group: "Access", label: "Authentication", value: "auth", description: "Require a JWT, OIDC, OAuth2, Paseto, API key or basic credential." },
  { group: "Access", label: "Forward auth", value: "forwardauth", description: "Ask an external service whether to allow each request." },
  { group: "Access", label: "OpenID Connect login", value: "oidc", description: "Send browsers to an identity provider to sign in." },
  { group: "Access", label: "HMAC signature", value: "hmac", description: "Require each request to carry a valid signature." },
  { group: "Access", label: "TLS session binding", value: "tls_binding", description: "Tie the session cookie to the client certificate." },
  { group: "Access", label: "Client certificate header", value: "xfcc", description: "Pass the client certificate to the backend as X-Forwarded-Client-Cert." },
  { group: "Access", label: "IP filter", value: "ipfilter", description: "Allow or deny by client address or network." },
  { group: "Access", label: "GeoIP", value: "geoip", description: "Allow or deny by the client's country." },
  { group: "Access", label: "Access policy (CEL)", value: "policy", description: "Allow or deny by an expression over the request." },

  { group: "Protection", label: "WAF", value: "waf", description: "Inspect requests for attacks and refuse them." },
  { group: "Protection", label: "Bot management", value: "bot_management", description: "Tell browsers from scripts and decide what each may do." },
  { group: "Protection", label: "Proof of work challenge", value: "pow", description: "Make a client spend CPU before it is served." },
  { group: "Protection", label: "Cloudflare Turnstile", value: "turnstile", description: "Require a Turnstile token." },
  { group: "Protection", label: "File upload security", value: "file_security", description: "Scan uploads by signature and refuse what matches." },
  { group: "Protection", label: "Security headers", value: "security_headers", description: "Add the response headers browsers use to protect users." },
  { group: "Protection", label: "GraphQL firewall", value: "graphql_firewall", description: "Limit query depth, complexity and introspection." },
  { group: "Protection", label: "JSON schema validation", value: "schema_validation", description: "Refuse a body that does not match a schema." },
  { group: "Protection", label: "Honeypot", value: "honeypot", description: "Answer paths only scanners visit, and mark who visits them." },
  { group: "Protection", label: "Deception", value: "deception", description: "Serve decoys to a client already marked as hostile." },
  { group: "Protection", label: "Tarpit", value: "tarpit", description: "Slow down a client whose threat score is above a threshold." },
  { group: "Protection", label: "Body entropy", value: "entropy", description: "Record a body that looks encrypted or packed." },
  { group: "Protection", label: "XSS recognition", value: "xss_recognition", description: "Recognise cross-site scripting in parameters." },
  { group: "Protection", label: "SQL injection recognition", value: "sqli_recognition", description: "Recognise SQL injection in parameters." },
  { group: "Protection", label: "Threat recognition", value: "threat_recognition", description: "Score each request against the known attack patterns." },

  { group: "Headers and paths", label: "Headers", value: "headers", description: "Add, set or remove request and response headers." },
  { group: "Headers and paths", label: "Forwarded headers", value: "forwardedheaders", description: "Set or trust X-Forwarded-Proto." },
  { group: "Headers and paths", label: "Request ID", value: "request_id", description: "Give every request an identifier." },
  { group: "Headers and paths", label: "Path rewrite", value: "rewrite", description: "Rewrite the path and query before forwarding." },
  { group: "Headers and paths", label: "Add prefix", value: "addprefix", description: "Prepend a path prefix." },
  { group: "Headers and paths", label: "Strip prefix", value: "stripprefix", description: "Remove a path prefix." },
  { group: "Headers and paths", label: "Strip prefix by regex", value: "stripprefixregex", description: "Remove whatever a pattern matches at the start of the path." },
  { group: "Headers and paths", label: "Replace path", value: "replacepath", description: "Forward every request to one path." },
  { group: "Headers and paths", label: "Replace path by regex", value: "replacepathregex", description: "Replace what a pattern matches in the path." },
  { group: "Headers and paths", label: "CORS", value: "cors", description: "Answer browsers' cross-origin preflights." },
  { group: "Headers and paths", label: "gRPC-Web", value: "grpcweb", description: "Let browsers call a gRPC backend." },
  { group: "Headers and paths", label: "Custom errors", value: "errors", description: "Serve your own pages for error statuses." },

  { group: "Traffic shaping", label: "Response cache", value: "cache", description: "Serve repeated responses from memory." },
  { group: "Traffic shaping", label: "Compression", value: "compress", description: "Compress responses with gzip or brotli." },
  { group: "Traffic shaping", label: "Retry", value: "retry", description: "Try another target when one fails." },
  { group: "Traffic shaping", label: "Body transformation", value: "transform", description: "Rewrite request or response bodies." },
  { group: "Traffic shaping", label: "WebAssembly", value: "wasm", description: "Run your own module on each request." },

  { group: "Observability", label: "Access logging", value: "accesslog", description: "Write a line per request for this route." },
  { group: "Observability", label: "Prometheus metrics", value: "metrics", description: "Count and time this route's requests." },
];

/** The catalog entry for a type, or undefined for one the catalog does not know. */
export function policyType(value: string | undefined): MiddlewareTypeOption | undefined {
  return MIDDLEWARE_TYPES.find((t) => t.value === value);
}

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
