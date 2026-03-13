/**
 * RuleBuilder: visual rule builder for HTTP/gRPC routes.
 * Serializes to/from the rule format: Host(`x`), PathPrefix(`y`), Methods(`GET`), etc.
 * Combines conditions with && (and) or || (or).
 */

import { useState, useEffect, useCallback, useRef } from "react";
import {
  Stack,
  Group,
  Select,
  TextInput,
  MultiSelect,
  Button,
  Paper,
  Text,
  SegmentedControl,
  Alert,
} from "@mantine/core";
import { IconPlus, IconTrash } from "@tabler/icons-react";

export type RuleConditionType =
  | "Host"
  | "Path"
  | "PathPrefix"
  | "PathRegex"
  | "Methods"
  | "Headers";

export type RuleCondition = {
  id: string;
  type: RuleConditionType;
  value: string;
  value2?: string; // for Headers: header value
  combineWithNext: "and" | "or";
};

const CONDITION_TYPES: { value: RuleConditionType; label: string; description: string }[] = [
  { value: "Host", label: "Host", description: "Match hostname (e.g. example.com or *.example.com)" },
  { value: "Path", label: "Path", description: "Exact path match" },
  { value: "PathPrefix", label: "Path prefix", description: "Path starts with" },
  { value: "PathRegex", label: "Path regex", description: "Path matches regex" },
  { value: "Methods", label: "HTTP methods", description: "Match request methods" },
  { value: "Headers", label: "Header", description: "Header name and value" },
];

const HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"];

function nextId() {
  return `cond-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

function escapeForRule(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/`/g, "\\`");
}

function serializeCondition(c: RuleCondition): string {
  const v = c.value.trim();
  if (!v) return "";
  switch (c.type) {
    case "Host":
      return `Host(\`${escapeForRule(v)}\`)`;
    case "Path":
      return `Path(\`${escapeForRule(v)}\`)`;
    case "PathPrefix":
      return `PathPrefix(\`${escapeForRule(v)}\`)`;
    case "PathRegex":
      return `PathRegex(\`${escapeForRule(v)}\`)`;
    case "Methods": {
      const methods = v
        .split(/[,\s]+/)
        .map((m) => m.trim().toUpperCase())
        .filter(Boolean);
      if (methods.length === 0) return "";
      return `Methods(\`${methods.map(escapeForRule).join("`, `")}\`)`;
    }
    case "Headers": {
      const v2 = (c.value2 || "").trim();
      if (!v2) return "";
      return `Headers(\`${escapeForRule(v)}\`, \`${escapeForRule(v2)}\`)`;
    }
    default:
      return "";
  }
}

export function conditionsToRule(conditions: RuleCondition[]): string {
  const valid = conditions.filter((c) => {
    const s = serializeCondition(c);
    return s.length > 0;
  });
  if (valid.length === 0) return "";
  return valid
    .map((c, i) => {
      const part = serializeCondition(c);
      const isLast = i === valid.length - 1;
      const op = c.combineWithNext === "or" ? " || " : " && ";
      return isLast ? part : part + op;
    })
    .join("");
}

function parseSingleCondition(part: string): RuleCondition | null {
  const hostMatch = part.match(/^Host\(`([^`]*)`\)$/);
  if (hostMatch) {
    return {
      id: nextId(),
      type: "Host",
      value: hostMatch[1],
      combineWithNext: "and",
    };
  }
  const pathPrefixMatch = part.match(/^PathPrefix\(`([^`]*)`\)$/);
  if (pathPrefixMatch) {
    return {
      id: nextId(),
      type: "PathPrefix",
      value: pathPrefixMatch[1],
      combineWithNext: "and",
    };
  }
  const pathMatch = part.match(/^Path\(`([^`]*)`\)$/);
  if (pathMatch) {
    return {
      id: nextId(),
      type: "Path",
      value: pathMatch[1],
      combineWithNext: "and",
    };
  }
  const pathRegexMatch = part.match(/^PathRegex\(`([^`]*)`\)$/);
  if (pathRegexMatch) {
    return {
      id: nextId(),
      type: "PathRegex",
      value: pathRegexMatch[1],
      combineWithNext: "and",
    };
  }
  const methodsMatch = part.match(/^Methods\(`([^`]*(?:`, `[^`]*)*)`\)$/);
  if (methodsMatch) {
    const inner = methodsMatch[1];
    const methods = inner.split("`, `").map((s) => s.trim());
    return {
      id: nextId(),
      type: "Methods",
      value: methods.join(", "),
      combineWithNext: "and",
    };
  }
  const headersMatch = part.match(/^Headers\(`([^`]*)`, `([^`]*)`\)$/);
  if (headersMatch) {
    return {
      id: nextId(),
      type: "Headers",
      value: headersMatch[1],
      value2: headersMatch[2],
      combineWithNext: "and",
    };
  }
  return null;
}

export function parseRuleToConditions(rule: string): RuleCondition[] {
  if (!rule || !rule.trim()) return [];
  const trimmed = rule.trim();
  if (trimmed === "L4()") return [];

  // Split by && or ||, preserving which separator was used
  const re = /\s+(&&|\|\|)\s+/g;
  const parts: string[] = [];
  const ops: ("and" | "or")[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = re.exec(trimmed)) !== null) {
    parts.push(trimmed.slice(lastIndex, match.index).trim());
    ops.push(match[1] === "||" ? "or" : "and");
    lastIndex = match.index + match[0].length;
  }
  parts.push(trimmed.slice(lastIndex).trim());

  const conditions: RuleCondition[] = [];
  for (let i = 0; i < parts.length; i++) {
    const c = parseSingleCondition(parts[i]);
    if (c) {
      c.combineWithNext = i < ops.length ? ops[i] : "and";
      conditions.push(c);
    }
  }
  return conditions;
}

interface RuleBuilderProps {
  value: string;
  onChange: (rule: string) => void;
  onBlur?: () => void;
  required?: boolean;
  error?: string;
}

export function RuleBuilder({
  value,
  onChange,
  onBlur,
  required,
  error,
}: RuleBuilderProps) {
  const [conditions, setConditions] = useState<RuleCondition[]>(() =>
    value && value !== "L4()" ? parseRuleToConditions(value) : []
  );
  const [parseFailed, setParseFailed] = useState(false);
  const lastEmittedRef = useRef("");

  // Sync from parent value when it changes externally (e.g. form reset, edit different route)
  useEffect(() => {
    if (!value || value === "L4()") {
      setConditions([]);
      setParseFailed(false);
      return;
    }
    if (value === lastEmittedRef.current) return;
    const parsed = parseRuleToConditions(value);
    if (parsed.length > 0) {
      setConditions(parsed);
      setParseFailed(false);
    } else if (value.trim()) {
      setParseFailed(true);
    }
  }, [value]);

  const syncToParent = useCallback(
    (conds: RuleCondition[]) => {
      const rule = conditionsToRule(conds);
      lastEmittedRef.current = rule;
      onChange(rule);
    },
    [onChange]
  );

  const addCondition = () => {
    const next: RuleCondition = {
      id: nextId(),
      type: "PathPrefix",
      value: "/api",
      combineWithNext: "and",
    };
    const nextConds = [...conditions, next];
    setConditions(nextConds);
    syncToParent(nextConds);
  };

  const updateCondition = (id: string, update: Partial<RuleCondition>) => {
    const nextConds = conditions.map((c) =>
      c.id === id ? { ...c, ...update } : c
    );
    setConditions(nextConds);
    syncToParent(nextConds);
  };

  const removeCondition = (id: string) => {
    const nextConds = conditions.filter((c) => c.id !== id);
    setConditions(nextConds);
    syncToParent(nextConds);
  };

  const moveCombineOp = (id: string, op: "and" | "or") => {
    updateCondition(id, { combineWithNext: op });
  };

  const generatedRule = conditionsToRule(conditions);
  const hasError = required && !generatedRule.trim();
  const displayError = error || (hasError ? "Add at least one condition" : undefined);

  return (
    <Stack gap="md">
      <Group justify="space-between" align="center">
        <Text size="sm" fw={600} c={displayError ? "red" : undefined}>
          Match conditions
        </Text>
        <Button
          variant="light"
          size="xs"
          leftSection={<IconPlus size={14} />}
          onClick={addCondition}
        >
          Add condition
        </Button>
      </Group>

      {parseFailed && (
        <Alert color="orange" variant="light" title="Could not fully parse rule">
          Some parts of the rule were not recognized. Adding new conditions will replace the rule.
        </Alert>
      )}

      {conditions.length === 0 ? (
        <Paper p="md" withBorder radius="md" bg="gray.0">
          <Text size="sm" c="dimmed" ta="center">
            No conditions yet. Click "Add condition" to build your match rule.
          </Text>
          <Button
            variant="subtle"
            size="sm"
            mt="sm"
            leftSection={<IconPlus size={14} />}
            onClick={addCondition}
            fullWidth
          >
            Add first condition
          </Button>
        </Paper>
      ) : (
        <Stack gap="xs">
          {conditions.map((c, idx) => (
            <ConditionRow
              key={c.id}
              condition={c}
              isLast={idx === conditions.length - 1}
              onUpdate={(u) => updateCondition(c.id, u)}
              onRemove={() => removeCondition(c.id)}
              onCombineChange={(op) => moveCombineOp(c.id, op)}
            />
          ))}
        </Stack>
      )}

      {generatedRule && (
        <Paper p="xs" withBorder radius="md" bg="dark.8">
          <Text size="xs" c="dimmed" mb={4}>
            Generated rule
          </Text>
          <Text size="xs" ff="monospace" c="gray.3" style={{ wordBreak: "break-all" }}>
            {generatedRule}
          </Text>
        </Paper>
      )}

      {displayError && (
        <Text size="xs" c="red">
          {displayError}
        </Text>
      )}
    </Stack>
  );
}

function ConditionRow({
  condition,
  isLast,
  onUpdate,
  onRemove,
  onCombineChange,
}: {
  condition: RuleCondition;
  isLast: boolean;
  onUpdate: (u: Partial<RuleCondition>) => void;
  onRemove: () => void;
  onCombineChange: (op: "and" | "or") => void;
}) {
  const typeMeta = CONDITION_TYPES.find((t) => t.value === condition.type);

  return (
    <Paper p="sm" withBorder radius="md">
      <Stack gap="xs">
        <Group wrap="nowrap" align="flex-start" gap="xs">
          <Select
            label="Type"
            size="xs"
            data={CONDITION_TYPES.map((t) => ({ value: t.value, label: t.label }))}
            value={condition.type}
            onChange={(v) => onUpdate({ type: (v as RuleConditionType) || "PathPrefix" })}
            w={140}
          />
          <ConditionValueInput condition={condition} onUpdate={onUpdate} />
          <Button
            variant="subtle"
            color="red"
            size="xs"
            mt={22}
            onClick={onRemove}
            title="Remove condition"
          >
            <IconTrash size={14} />
          </Button>
        </Group>
        {typeMeta && (
          <Text size="xs" c="dimmed">
            {typeMeta.description}
          </Text>
        )}
        {!isLast && (
          <SegmentedControl
            size="xs"
            data={[
              { value: "and", label: "AND (all must match)" },
              { value: "or", label: "OR (any can match)" },
            ]}
            value={condition.combineWithNext}
            onChange={(v) => onCombineChange(v as "and" | "or")}
          />
        )}
      </Stack>
    </Paper>
  );
}

function ConditionValueInput({
  condition,
  onUpdate,
}: {
  condition: RuleCondition;
  onUpdate: (u: Partial<RuleCondition>) => void;
}) {
  switch (condition.type) {
    case "Host":
      return (
        <TextInput
          label="Host"
          placeholder="example.com or *.example.com"
          size="xs"
          value={condition.value}
          onChange={(e) => onUpdate({ value: e.target.value })}
          style={{ flex: 1 }}
        />
      );
    case "Path":
      return (
        <TextInput
          label="Path"
          placeholder="/exact/path"
          size="xs"
          value={condition.value}
          onChange={(e) => onUpdate({ value: e.target.value })}
          style={{ flex: 1 }}
        />
      );
    case "PathPrefix":
      return (
        <TextInput
          label="Path prefix"
          placeholder="/api"
          size="xs"
          value={condition.value}
          onChange={(e) => onUpdate({ value: e.target.value })}
          style={{ flex: 1 }}
        />
      );
    case "PathRegex":
      return (
        <TextInput
          label="Regex"
          placeholder="^/api/v[0-9]+/"
          size="xs"
          value={condition.value}
          onChange={(e) => onUpdate({ value: e.target.value })}
          style={{ flex: 1 }}
        />
      );
    case "Methods":
      return (
        <MultiSelect
          label="Methods"
          placeholder="Select methods"
          size="xs"
          data={HTTP_METHODS.map((m) => ({ value: m, label: m }))}
          value={condition.value ? condition.value.split(",").map((s) => s.trim()).filter(Boolean) : []}
          onChange={(v) => onUpdate({ value: v.join(", ") })}
          style={{ flex: 1 }}
        />
      );
    case "Headers":
      return (
        <Group style={{ flex: 1 }} align="flex-end" wrap="nowrap">
          <TextInput
            label="Header name"
            placeholder="X-Version"
            size="xs"
            value={condition.value}
            onChange={(e) => onUpdate({ value: e.target.value })}
            style={{ flex: 1 }}
          />
          <TextInput
            label="Header value"
            placeholder="v2"
            size="xs"
            value={condition.value2 || ""}
            onChange={(e) => onUpdate({ value2: e.target.value })}
            style={{ flex: 1 }}
          />
        </Group>
      );
    default:
      return null;
  }
}
