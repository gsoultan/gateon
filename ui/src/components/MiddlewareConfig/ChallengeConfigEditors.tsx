// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Editors for the middleware types the picker did not offer before (truth
// T36 / NEW-8). Each writes exactly the keys the gateway's factory reads, in
// the spelling it reads them (internal/middleware/factory.go); the
// descriptions say what an empty value means there.

import { Stack, TextInput, NumberInput, Switch, Text, TagsInput } from "@mantine/core";
import { StoredSecretInput } from "../settings/StoredSecretInput";
import { entropyProblem, tarpitProblem } from "./middlewareConfigProblems";

interface EditorProps {
  config: Record<string, string>;
  updateConfig: (key: string, value: string) => void;
}

const splitTags = (val: string | undefined) => (val || "").split(",").map((s) => s.trim()).filter(Boolean);
const joinTags = (tags: string[]) => tags.join(", ");
const numberOrEmpty = (v: string | undefined) => (v === undefined || v === "" ? "" : Number(v));
const toConfig = (v: string | number) => (v === "" ? "" : String(v));

/** Proof of work: a client whose threat score exceeds the threshold solves a puzzle first. */
export function PowConfigEditor({ config, updateConfig }: EditorProps) {
  return (
    <Stack gap="md">
      <NumberInput
        label="Difficulty"
        description="Leading zero hex digits the client's hash must have. Each step is 16 times the work. Empty: 4."
        placeholder="4"
        value={numberOrEmpty(config.difficulty)}
        onChange={(v) => updateConfig("difficulty", toConfig(v))}
        min={1}
        max={8}
      />
      <NumberInput
        label="Threat Score Threshold"
        description="Challenge a client whose threat score (100 minus its reputation) is above this. Empty: 20."
        placeholder="20"
        value={numberOrEmpty(config.threshold)}
        onChange={(v) => updateConfig("threshold", toConfig(v))}
        min={0}
        max={100}
      />
      <StoredSecretInput
        label="Secret"
        description="Signs the challenges and passes. Empty: a key generated at start-up, so challenges do not survive a restart and are not shared between instances."
        value={config.secret || ""}
        onChange={(v) => updateConfig("secret", v)}
        clearable
      />
    </Stack>
  );
}

/** Tarpit: slows a client whose threat score reaches the threshold. */
export function TarpitConfigEditor({ config, updateConfig }: EditorProps) {
  return (
    <Stack gap="md">
      <NumberInput
        label="Threat Score Threshold"
        description="Delay a client whose threat score (100 minus its reputation) is at least this. Required: above 0."
        placeholder="50"
        value={numberOrEmpty(config.threshold)}
        onChange={(v) => updateConfig("threshold", toConfig(v))}
        min={0}
        max={100}
        error={tarpitProblem(config)}
      />
      <TextInput
        label="Base Delay"
        description="Delay at the threshold, growing with the score (Go duration, e.g. 500ms)."
        placeholder="500ms"
        value={config.base_delay || ""}
        onChange={(e) => updateConfig("base_delay", e.currentTarget.value)}
      />
      <TextInput
        label="Maximum Delay"
        description="No request is held longer than this (Go duration, e.g. 5s). Each held request keeps its connection open."
        placeholder="5s"
        value={config.max_delay || ""}
        onChange={(e) => updateConfig("max_delay", e.currentTarget.value)}
      />
    </Stack>
  );
}

/** Body entropy: records request bodies that look encrypted or packed. */
export function EntropyConfigEditor({ config, updateConfig }: EditorProps) {
  return (
    <NumberInput
      label="Entropy Threshold (bits per byte)"
      description="A request body above this Shannon entropy is recorded as a threat; the request is still forwarded. Random or encrypted data is close to 8; text is 4 to 5. Above 0, at most 8. Empty: 7.5."
      placeholder="7.5"
      value={numberOrEmpty(config.threshold)}
      onChange={(v) => updateConfig("threshold", toConfig(v))}
      min={0}
      max={8}
      decimalScale={2}
      error={entropyProblem(config)}
    />
  );
}

/** GraphQL firewall: query depth, cost and introspection limits. */
export function GraphQLFirewallConfigEditor({ config, updateConfig }: EditorProps) {
  return (
    <Stack gap="md">
      <NumberInput
        label="Maximum Depth"
        description="Refuse a query nested deeper than this. Empty or 0: no limit."
        value={numberOrEmpty(config.max_depth)}
        onChange={(v) => updateConfig("max_depth", toConfig(v))}
        min={0}
      />
      <NumberInput
        label="Maximum Complexity"
        description="Refuse a query whose total field cost exceeds this. Empty or 0: no limit."
        value={numberOrEmpty(config.max_complexity)}
        onChange={(v) => updateConfig("max_complexity", toConfig(v))}
        min={0}
      />
      <Switch
        label="Allow Introspection"
        description="Off refuses __schema and __type queries, which map the whole API for an attacker."
        checked={config.introspection === "true"}
        onChange={(e) => updateConfig("introspection", e.currentTarget.checked ? "true" : "false")}
      />
    </Stack>
  );
}

/** Deception: trap paths, invisible links, hidden forms and a canary header. */
export function DeceptionConfigEditor({ config, updateConfig }: EditorProps) {
  return (
    <Stack gap="md">
      <TagsInput
        label="Honeypot Paths"
        description="A request to one of these paths (or below them) is refused with 403 and recorded as a critical threat."
        placeholder="/.env, /backup.zip"
        value={splitTags(config.honeypot_paths)}
        onChange={(v) => updateConfig("honeypot_paths", joinTags(v))}
        clearable
      />
      <Switch
        label="Inject Invisible Links"
        description="Add the paths below as links no person sees to HTML responses; a client that follows one is refused. On unless switched off."
        checked={config.inject_invisible_links !== "false"}
        onChange={(e) => updateConfig("inject_invisible_links", e.currentTarget.checked ? "true" : "false")}
      />
      <TagsInput
        label="Invisible Link Paths"
        placeholder="/admin-old"
        value={splitTags(config.invisible_link_paths)}
        onChange={(v) => updateConfig("invisible_link_paths", joinTags(v))}
        clearable
      />
      <TagsInput
        label="Honey Form Paths"
        description="Paths of hidden forms added to HTML responses; a submission to one is refused."
        value={splitTags(config.honey_forms)}
        onChange={(v) => updateConfig("honey_forms", joinTags(v))}
        clearable
      />
      <Switch
        label="Troll Response"
        description="Answer a trapped client whose reputation is already low with an endless stream of junk instead of a 403. Each one holds a connection until the client gives up."
        checked={config.enable_troll_response === "true"}
        onChange={(e) => updateConfig("enable_troll_response", e.currentTarget.checked ? "true" : "false")}
      />
      <TextInput
        label="Canary Header"
        placeholder="X-Canary"
        value={config.canary_header || ""}
        onChange={(e) => updateConfig("canary_header", e.currentTarget.value)}
      />
      <StoredSecretInput
        label="Canary Token"
        description="Sent in the canary header on every response; a request that sends it back is replaying what it scraped, and is refused."
        value={config.canary_token || ""}
        onChange={(v) => updateConfig("canary_token", v)}
        clearable
      />
    </Stack>
  );
}

/** The recognition middlewares take no configuration. */
export function RecognitionConfigEditor({ type }: { type: string }) {
  const what: Record<string, string> = {
    xss_recognition: "cross-site scripting",
    sqli_recognition: "SQL injection",
    threat_recognition: "cross-site scripting, SQL injection and other attack patterns",
  };
  return (
    <Text size="sm" c="dimmed">
      Inspects each request for {what[type] ?? "attack patterns"} and records what it finds. No configuration.
    </Text>
  );
}
