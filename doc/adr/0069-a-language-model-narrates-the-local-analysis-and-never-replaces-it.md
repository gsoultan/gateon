# 69. A language model narrates the local analysis and never replaces it

Date: 2026-10-14

## Status

Accepted.

## Context

The dashboard has two features called AI:

- the Security Hub's **AI Advisory** (`POST /v1/AnalyzeConfig`);
- the Live Logs **AI Log Assistant** (`POST /v1/AnalyzeLogs`).

Both are a deterministic engine that runs on the gateway. Operators asked for
them to work with a real model: Anthropic's Claude, OpenAI's ChatGPT, or a
self-hosted model behind an OpenAI-compatible API (Ollama, vLLM, LM Studio).

A model is a third party that sees what it is sent, costs money per call, can
be slow or down, and can be steered by the text it reads. The log lines the
Log Assistant reads are written by the gateway's clients, some of them
hostile.

## Decision

**The model narrates. It never replaces the local result.** The local analysis
always runs first, whether or not a provider is configured:

- The advisory's findings are always the local ones. The model is shown them
  and writes the executive summary. It cannot add, drop or reword a finding.
- The Log Assistant returns the local tally beside the model's analysis
  (`local`), so the operator always sees what the lines actually say.

**Every failure falls back to the local result.** A response names its
`engine`: `local`, or `provider:model`. When a provider is configured but did
not answer, the response adds a `notice` saying why. The notice is one of the
`internal/ai/llm` sentinels, so it never carries the key, the prompt, the
provider's reply or its address. The full error goes to the server log.

**The model is never on the request path.** It is called only from the two
management endpoints and from a test endpoint. No detection, routing or
blocking decision reads it.

**The setting: `GlobalConfig.ai` (`AIConfig`).**

- **Fields:** `enabled`, `provider`, `model`, `base_url`, `api_key`,
  `timeout_seconds`, `max_output_tokens`, `share_log_lines`.
- **Providers:** `anthropic` (Messages API), `openai` (chat completions), and
  `openai_compatible` (chat completions; `base_url` and `model` required, key
  optional).
- **Where it is stored:** in `global.json` with the rest of the global
  configuration, so there is no database migration.
- **One save path.** REST, Connect, gRPC and the dashboard all save through
  `UpdateGlobalConfig`, which runs `llm.Validate`. An enabled configuration the
  gateway could never call is refused with `InvalidArgument`, naming the field.
- **Administrator-only** (`globalbound`, ADR 0040). The setting decides where
  findings and log lines are sent. An operator who could change it could read
  the gateway's logs from a server of their own.
- **The key is a stored secret** (ADR 0028):
  - The API returns it as the placeholder, and `$env:`, `$vault:` and `$aws-sm:`
    references work.
  - Its destination is the provider and the origin of `base_url`. A save that
    keeps the placeholder while changing either is refused (`ErrMoved`), so the
    stored key cannot be pointed at another host.

**Bounds.** Every one is explicit:

| Bound | Value |
| --- | --- |
| Per-call timeout | 30 s default, 120 s cap |
| Output tokens | 4096 default, 16000 cap |
| Reply read | 1 MiB |
| Answer returned | 16 KiB |
| Findings sent | 40 |
| Log lines sent | 50, each 1 KiB |
| Calls in flight gateway-wide | 2; one more is refused (`ErrBusy`) and falls back, never queued |
| Summary cache | 1 entry, 5 min, keyed by settings and findings (the tab analyses on every open) |

**Transport.**

- **No redirects.** Go strips `Authorization` on a cross-host redirect but not
  `x-api-key`.
- **https only**, except http to `localhost` or a loopback or private address
  literal: the self-hosted model case. A hostname is not trusted to stay local.
  `base_url` may not carry credentials, a query or a fragment.
- **Raw HTTP, not an SDK.** Each provider is one request shape over one shared
  client, so the limits above hold for all three. It adds no dependency to the
  module graph that `govulncheck` and the release SBOM cover.

**What leaves the gateway.**

- **Advisory:** the local findings (title, severity, description,
  recommendation), never the configuration itself.
- **Log Assistant:** by default only the local tally. With `share_log_lines`,
  also the lines, with credentials masked by `redact.Text`.
- **Prompt injection.** Variable text is quoted inside tags that the fixed
  system prompt names as data. `<`, `>` and newlines are folded out of every
  quoted value, so a line cannot close its block. The model has no tools, and
  its answer is rendered as plain text, never markdown or HTML. A line that
  talks the model into a misleading summary can mislead only that summary,
  and the local tally sits beside it.

## Consequences

- An operator can use Claude, ChatGPT or a local model with no code change,
  and turning it off returns exactly the previous behaviour.
- Defaults: Anthropic `claude-opus-5-5`, OpenAI `gpt-5`. Thinking is left to
  the model's default, which counts against `max_output_tokens`, hence the
  4096 default.
- Anthropic `refusal` stop reasons and OpenAI `refusal` fields count as no
  answer and fall back.
- **Every transport serves the analysis.** It lives in `internal/ai/advisory`
  and is exposed as three `ApiService` RPCs: `AnalyzeConfig`, `AnalyzeLogs`
  and `TestAIProvider`. REST (`POST /v1/AnalyzeConfig`, `/v1/AnalyzeLogs`,
  `/v1/ai-advisory/test`), Connect and gRPC all call them, and `apiPermissions`
  maps them like their REST twins: read on diagnostics for the two analyses,
  write on global for the test. One `advisory.Service` per `ApiService`, so the
  concurrency bound and summary cache hold across transports.
- The package reads no listener code. Whether the management listener is open
  to the world is asked of `internal/server/entrypoint` by the server and
  handed in, as `posture.Config.ManagementWorldOpen` already is.
