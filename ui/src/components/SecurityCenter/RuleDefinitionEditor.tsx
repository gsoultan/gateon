import { useMemo } from 'react';
import {
  Alert,
  Group,
  JsonInput,
  MultiSelect,
  NumberInput,
  Select,
  Stack,
  Text,
  TextInput,
} from '@mantine/core';
import { IconAlertTriangle, IconInfoCircle } from '@tabler/icons-react';

/**
 * The WAF engine no longer parses SecLang, so a rule is a typed definition
 * rather than a ModSecurity directive.
 *
 * The editor is deliberately a structured form over a JSON document rather than
 * a free-text box: every field here maps to exactly one field the engine
 * understands, and a rule that does not compile is rejected when it is saved.
 * Under SecLang a mistyped directive was accepted and produced a rule that
 * silently never fired, which is the failure this whole format exists to
 * remove — so the editor should not be the one place it comes back.
 */

/** Phases, in the order a request passes through them. */
const PHASES = [
  { value: 'request_headers', label: 'Request headers (before the body is read)' },
  { value: 'request_body', label: 'Request body and arguments' },
  { value: 'response_headers', label: 'Response headers' },
  { value: 'response_body', label: 'Response body (data-leak rules)' },
];

/** Collections a rule can inspect, named after the SecLang ones they replace. */
const TARGETS = [
  { value: 'args', label: 'ARGS — query and body arguments' },
  { value: 'arg_names', label: 'ARGS_NAMES — argument names' },
  { value: 'uri', label: 'REQUEST_URI — full target, including the query' },
  { value: 'path', label: 'REQUEST_PATH — path only' },
  { value: 'headers', label: 'REQUEST_HEADERS — header values' },
  { value: 'header_names', label: 'REQUEST_HEADER_NAMES' },
  { value: 'body', label: 'REQUEST_BODY — raw body' },
  { value: 'filenames', label: 'FILES_NAMES — uploaded file names' },
  { value: 'cookies', label: 'REQUEST_COOKIES' },
  { value: 'method', label: 'REQUEST_METHOD' },
  { value: 'remote_addr', label: 'REMOTE_ADDR' },
  { value: 'resp_headers', label: 'RESPONSE_HEADERS' },
  { value: 'resp_body', label: 'RESPONSE_BODY' },
];

const OPERATORS = [
  { value: 'regex', label: 'regex — RE2 pattern (@rx)' },
  { value: 'contains', label: 'contains — substring (@contains)' },
  { value: 'contains_any', label: 'contains_any — any of a list (@pm)' },
  { value: 'equals', label: 'equals — exact value' },
  { value: 'prefix', label: 'prefix — starts with' },
  { value: 'present', label: 'present — the value exists at all' },
  { value: 'segment_count', label: 'segment_count — at least N separators' },
];

const TRANSFORMS = [
  { value: 'urldecode', label: 'urldecode — percent-decode first' },
  { value: 'lowercase', label: 'lowercase' },
  { value: 'compress_whitespace', label: 'compress_whitespace' },
  { value: 'remove_whitespace', label: 'remove_whitespace' },
  { value: 'normalize_path', label: 'normalize_path' },
];

const SEVERITIES = ['notice', 'warning', 'error', 'critical'];

/**
 * Confidence decides whether the rule survives the configured paranoia level,
 * so it is a statement about false positives rather than about importance.
 */
const CONFIDENCES = [
  { value: 'certain', label: 'certain — no known false positives (PL1)' },
  { value: 'high', label: 'high — rare, well-understood false positives (PL1)' },
  { value: 'medium', label: 'medium — fires on unusual but legitimate traffic (PL2)' },
  { value: 'low', label: 'low — a heuristic needing tuning (PL3)' },
  { value: 'heuristic', label: 'heuristic — research grade (PL4)' },
];

interface OperatorDef {
  kind?: string;
  pattern?: string;
  values?: string[];
  min?: number;
  separator?: string;
  key_suffix?: string;
}

interface Definition {
  phase?: string;
  targets?: string[];
  transforms?: string[];
  operator?: OperatorDef;
  action?: string;
  status?: number;
  severity?: string;
  confidence?: string;
  msg?: string;
  tags?: string[];
}

const EMPTY: Definition = {
  phase: 'request_body',
  targets: ['args'],
  transforms: ['urldecode', 'lowercase'],
  operator: { kind: 'contains', pattern: '' },
  severity: 'critical',
  confidence: 'high',
  msg: '',
};

interface Props {
  /** The stored rule body, as a JSON string. */
  value: string;
  onChange: (next: string) => void;
}

export function RuleDefinitionEditor({ value, onChange }: Props) {
  /**
   * A rule saved before the engine migration is still SecLang. It is shown
   * read-only with an explanation rather than silently reformatted: the
   * original text is the only record of what the rule was meant to do, and
   * guessing at a translation is exactly what a converter must not do.
   */
  const isLegacySecLang = useMemo(
    () => value.trim().length > 0 && !value.trim().startsWith('{'),
    [value],
  );

  const parsed = useMemo<Definition>(() => {
    if (!value.trim()) return EMPTY;
    try {
      return JSON.parse(value) as Definition;
    } catch {
      return EMPTY;
    }
  }, [value]);

  const parseError = useMemo(() => {
    if (!value.trim() || isLegacySecLang) return null;
    try {
      JSON.parse(value);
      return null;
    } catch (e) {
      return e instanceof Error ? e.message : 'Invalid JSON';
    }
  }, [value, isLegacySecLang]);

  const update = (patch: Partial<Definition>) => {
    onChange(JSON.stringify({ ...parsed, ...patch }, null, 2));
  };

  const updateOperator = (patch: Partial<OperatorDef>) => {
    update({ operator: { ...parsed.operator, ...patch } });
  };

  if (isLegacySecLang) {
    return (
      <Stack gap="xs">
        <Alert
          color="orange"
          icon={<IconAlertTriangle size={16} />}
          title="This rule is still written in SecLang and is not being enforced"
        >
          <Text size="sm">
            The WAF engine no longer parses SecLang. The original text is kept below so it
            can be re-created as a typed rule; nothing is running it in the meantime.
            Clear the field to start from a typed definition.
          </Text>
        </Alert>
        <JsonInput
          label="Original SecLang directive"
          value={value}
          onChange={onChange}
          minRows={4}
          autosize
          validationError={null}
          formatOnBlur={false}
        />
      </Stack>
    );
  }

  const kind = parsed.operator?.kind ?? 'contains';

  return (
    <Stack gap="sm">
      <Group grow align="flex-start">
        <Select
          label="Phase"
          description="When the rule runs"
          data={PHASES}
          value={parsed.phase ?? 'request_body'}
          onChange={(v) => update({ phase: v ?? 'request_body' })}
        />
        <Select
          label="Severity"
          data={SEVERITIES}
          value={parsed.severity ?? 'critical'}
          onChange={(v) => update({ severity: v ?? 'critical' })}
        />
      </Group>

      <MultiSelect
        label="Inspect"
        description="The collections this rule reads. A rule with none can never match."
        data={TARGETS}
        value={parsed.targets ?? []}
        onChange={(v) => update({ targets: v })}
        searchable
      />

      <MultiSelect
        label="Normalize before matching"
        description="Applied in order. Without urldecode a rule is bypassable by percent-encoding one character."
        data={TRANSFORMS}
        value={parsed.transforms ?? []}
        onChange={(v) => update({ transforms: v })}
      />

      <Group grow align="flex-start">
        <Select
          label="Match using"
          data={OPERATORS}
          value={kind}
          onChange={(v) => updateOperator({ kind: v ?? 'contains' })}
        />
        <Select
          label="Confidence"
          description="Decides which paranoia levels load the rule"
          data={CONFIDENCES}
          value={parsed.confidence ?? 'high'}
          onChange={(v) => update({ confidence: v ?? 'high' })}
        />
      </Group>

      {kind === 'contains_any' ? (
        <MultiSelect
          label="Any of these values"
          description="Press Enter to add each one"
          data={(parsed.operator?.values ?? []).map((v) => ({ value: v, label: v }))}
          value={parsed.operator?.values ?? []}
          onChange={(v) => updateOperator({ values: v })}
          searchable
        />
      ) : kind === 'segment_count' ? (
        <Group grow>
          <NumberInput
            label="At least"
            min={1}
            value={parsed.operator?.min ?? 15}
            onChange={(v) => updateOperator({ min: Number(v) })}
          />
          <TextInput
            label="Separator"
            placeholder="/"
            value={parsed.operator?.separator ?? ''}
            onChange={(e) => updateOperator({ separator: e.currentTarget.value })}
          />
        </Group>
      ) : kind === 'present' ? null : (
        <TextInput
          label={kind === 'regex' ? 'Pattern (RE2)' : 'Value'}
          placeholder={kind === 'regex' ? String.raw`\$\{jndi:` : 'evil'}
          required
          value={parsed.operator?.pattern ?? ''}
          onChange={(e) => updateOperator({ pattern: e.currentTarget.value })}
          description={
            kind === 'regex' ? (
              <Group gap={4} mt={4}>
                <IconInfoCircle size={14} />
                <Text size="xs">
                  RE2: no backreferences and no lookaround, so a pattern cannot be made to
                  run for exponential time.
                </Text>
              </Group>
            ) : undefined
          }
        />
      )}

      <Group grow align="flex-start">
        <TextInput
          label="Message"
          description="Shown when the rule blocks. A block with no message cannot be explained."
          required
          value={parsed.msg ?? ''}
          onChange={(e) => update({ msg: e.currentTarget.value })}
        />
        <NumberInput
          label="Block status"
          description="0 uses the policy default"
          min={0}
          max={599}
          value={parsed.status ?? 403}
          onChange={(v) => update({ status: Number(v) })}
        />
      </Group>

      {parseError && (
        <Alert color="red" icon={<IconAlertTriangle size={16} />} title="Invalid definition">
          <Text size="sm">{parseError}</Text>
        </Alert>
      )}
    </Stack>
  );
}
