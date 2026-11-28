// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { ActionIcon, Button, Group, Select, Stack, Text, TextInput } from "@mantine/core";
import { IconPlus, IconTrash } from "@tabler/icons-react";
import type { AIAgentRangeSource } from "../../../types/gateon";
import { AI_AGENT_NAMES, AI_AGENT_RANGES_HELP } from "../../MiddlewareConfig/botManagementCopy";

interface AIAgentRangesEditorProps {
  ranges: AIAgentRangeSource[];
  onChange: (ranges: AIAgentRangeSource[]) => void;
  disabled: boolean;
}

// The vendor address lists AI agent verification reads (ADR 0108). One row
// per list; an agent may have several.
export function AIAgentRangesEditor({ ranges, onChange, disabled }: AIAgentRangesEditorProps) {
  const update = (i: number, patch: AIAgentRangeSource) =>
    onChange(ranges.map((r, j) => (j === i ? { ...r, ...patch } : r)));

  return (
    <Stack gap="xs">
      <Text size="sm" fw={500}>AI Agent Address Lists</Text>
      <Text size="xs" c="dimmed">{AI_AGENT_RANGES_HELP}</Text>
      {ranges.length === 0 && (
        <Text size="xs" c="dimmed" fs="italic">
          No lists yet. Without one, no route can verify an AI agent, and a client that names one meets the
          route's other checks.
        </Text>
      )}
      {ranges.map((r, i) => (
        <Group key={i} align="flex-end" wrap="nowrap">
          <Select
            label={i === 0 ? "Agent" : undefined}
            aria-label="Agent"
            data={AI_AGENT_NAMES}
            value={r.agent || null}
            onChange={(val) => update(i, { agent: val || "" })}
            allowDeselect={false}
            disabled={disabled}
            w={200}
          />
          <TextInput
            label={i === 0 ? "List URL" : undefined}
            aria-label="List URL"
            placeholder="https://openai.com/gptbot.json"
            value={r.url || ""}
            onChange={(e) => update(i, { url: e.currentTarget.value })}
            disabled={disabled}
            style={{ flex: 1 }}
          />
          <ActionIcon
            variant="subtle"
            color="red"
            aria-label={`Remove the ${r.agent || "agent"} list ${r.url || ""}`.trim()}
            onClick={() => onChange(ranges.filter((_, j) => j !== i))}
            disabled={disabled}
            mb={4}
          >
            <IconTrash size={16} />
          </ActionIcon>
        </Group>
      ))}
      <Group>
        <Button
          variant="light"
          size="xs"
          leftSection={<IconPlus size={14} />}
          onClick={() => onChange([...ranges, { agent: "", url: "" }])}
          disabled={disabled}
        >
          Add list
        </Button>
      </Group>
    </Stack>
  );
}
