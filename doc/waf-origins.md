# WAF origins: off-origin redirect and SSRF detection

The WAF can tell "this URL points back at us" from "this URL points somewhere
else" only if it knows what *us* means. That list is `waf.origins`.

Leave it unset and Gateon derives it from the routing table. For a
host-routed gateway that is usually enough and there is nothing to do. For a
**path-routed** gateway it derives nothing, and two rules — open-redirect and
SSRF detection — go quiet while every other rule keeps working.

This page is about noticing that, and fixing it.

## Why it is configuration and not the Host header

The obvious implementation is to compare a destination against the request's
`Host` header. gwaf v0.4.0 did that, and it was wrong: the attacker writes the
`Host` header as freely as they write the destination. A request with

```http
Host: evil.tld
GET /?redirect_to=https://evil.tld/
```

compared same-origin and passed. The header says where the client claims to
have sent the request; it is not evidence about what this gateway is.

A route's rule, by contrast, is something the operator wrote down. That is why
origins come from configuration.

## Where the list comes from

In order:

1. **`waf.origins`**, if you set it.
2. Otherwise, the **`Host()` matchers in your route rules**.

Rule 2 is why most deployments never think about this. If your routes look like

```
Host(`api.example.com`) && PathPrefix(`/v1`)
Host(`app.example.com`)
```

then `api.example.com` and `app.example.com` are the origins, they track the
routing table as it changes, and the rules work.

Subdomains of a declared origin are already accepted by gwaf, so declare the
concrete parent rather than a pattern.

## When nothing is derived

**Wildcards are excluded, deliberately.** `Host(\`*\`)` is the catch-all every
default route uses. It is a matching pattern, not a name this gateway is
reachable at. Declaring it would hand the off-origin rules a literal `*` to
compare against, and the rule would appear enabled while never matching
anything — worse than being off, because it looks on. `*.example.com` is
excluded for the same reason.

**Path-only routes contribute nothing**, which is correct: they say what this
gateway *serves*, not what it is *called*.

So a routing table like this derives an empty list:

```
PathPrefix(`/api`)
PathPrefix(`/admin`)
Host(`*`)
```

That is an ordinary way to run a gateway. It is not a misconfiguration — but it
does mean you have to set `waf.origins` yourself, because nothing else can know
the answer.

## How to tell

Gateon says so at startup, once per WAF engine rather than per request:

```
WARN  WAF off-origin rules are inactive: no origins declared
      route=my-route
      hint=add Host() rules to routes, or set waf.origins, so redirect and
           SSRF destinations can be compared
```

and gwaf names the rule it has switched off:

```
WARN  gwaf: rule is inert without configured origins; off-origin redirect and
      SSRF detection is reporting nothing
      rule=1013  msg=Absolute URL in a redirect or fetch parameter
```

Both are `WARN` at startup. In a service that emits a lot of `DEBUG`, they are
easy to scroll past — if you have never gone looking, that is the most likely
reason you have not seen them.

## Setting it

In the global configuration:

```json
{
  "waf": {
    "enabled": true,
    "origins": ["example.com", "api.example.com"]
  }
}
```

Or in the dashboard: **Settings → WAF → Application Tuning → "Gateway
Origins"**. Or `PUT /v1/global`.

List the hostnames clients actually reach this gateway at. Include every name
that terminates here — a vanity domain, a CDN-facing name, an internal
hostname used by health checks — because a destination pointing at a name you
did not declare is treated as off-origin.

There is no environment variable for this; it is configuration, so that it
travels with the routing table it describes.

## What you lose while it is empty

Only the rules that need to compare two origins:

- **Open redirect** — a `redirect_to`-style parameter aimed off-site.
- **SSRF via absolute URL** — a parameter naming a destination the gateway
  would fetch.

Everything else — SQLi, XSS, shell and path injection, NoSQL, PHP, prompt
injection, the CRS ruleset — is unaffected. This is a narrow gap, but it is a
gap in exactly the class of attack where the payload looks like an ordinary URL.

## A worked check

If you want to confirm the rule is live rather than trusting the absence of a
warning, send a request with an absolute off-origin destination in a parameter
and confirm it is blocked:

```bash
curl -i 'https://api.example.com/search?next=https://evil.tld/'
```

With `waf.origins` containing `api.example.com`, that trips rule 1013. With an
empty origin list it passes, and nothing is logged, because the rule never
evaluated.

## See also

- [`security-posture.md`](./security-posture.md) — WAF/ClamAV/FIM freshness
  and the `GET /v1/security/posture` endpoint.
- [`adr/0004-waf-engine-replacement.md`](./adr/0004-waf-engine-replacement.md)
  — why the engine is gwaf, and what the migration covered.
