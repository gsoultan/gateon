// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import {
  Alert,
  Button,
  FileButton,
  Group,
  Select,
  Stack,
  Switch,
  Text,
  Textarea,
} from "@mantine/core";
import { useState } from "react";

import { LearnedSchemaDrafts } from "./LearnedSchemaDrafts";
import {
  OPENAPI_AUDIT_ONLY_NOTE,
  OPENAPI_MAX_BYTES,
  OPENAPI_MODE_HELP,
  OPENAPI_SPEC_HELP,
  SCHEMA_LEARNING_HELP,
} from "./wafCopy";

interface OpenApiSpecFieldsProps {
  config: Record<string, string>;
  updateConfig: (key: string, value: string) => void;
  /** Whether the route WAF is audit-only, which records whatever the mode says. */
  auditOnly: boolean;
}

/** Why a document cannot be used, or "" when it can. The gateway checks the rest on save. */
export function openApiSpecProblem(spec: string): string {
  // The limit is in bytes, and the document may hold non-ASCII descriptions.
  if (new Blob([spec]).size > OPENAPI_MAX_BYTES) {
    return `The document is larger than ${OPENAPI_MAX_BYTES >> 10} KiB. Remove examples and response schemas, which are not checked, or split the API across routes.`;
  }
  return "";
}

/**
 * Whether the mode select is shown. With a document, always. Without one, only
 * when a Refused is left over from a document since removed: a draft is not
 * offered into that, so it has to be visible to be changed.
 */
export function showsModeSelect(spec: string, mode: string): boolean {
  return spec !== "" || mode === "enforce";
}

interface SchemaLearningFieldsProps {
  config: Record<string, string>;
  updateConfig: (key: string, value: string) => void;
  onUse: (document: string) => void;
}

/** The learning switch and what has been learned. */
export function SchemaLearningFields({
  config,
  updateConfig,
  onUse,
}: SchemaLearningFieldsProps) {
  return (
    <>
      <Switch
        label="Learn this route's API from traffic"
        description={SCHEMA_LEARNING_HELP}
        checked={config.schema_learning === "true"}
        onChange={(e) =>
          updateConfig(
            "schema_learning",
            e.currentTarget.checked ? "true" : "false",
          )
        }
      />
      <LearnedSchemaDrafts
        hasDocument={(config.openapi_spec || "") !== ""}
        enforcing={config.openapi_mode === "enforce"}
        onUse={onUse}
      />
    </>
  );
}

// The OpenAPI section of the route WAF form. The document is a route setting
// only: it describes one API, and the global WAF fronts all of them.
export function OpenApiSpecFields({
  config,
  updateConfig,
  auditOnly,
}: OpenApiSpecFieldsProps) {
  const [fileProblem, setFileProblem] = useState("");
  const spec = config.openapi_spec || "";
  const mode = config.openapi_mode || "record";

  const loadFile = async (file: File | null) => {
    if (!file) return;
    setFileProblem("");
    try {
      const text = await file.text();
      const problem = openApiSpecProblem(text);
      if (problem) {
        setFileProblem(problem);
        return;
      }
      updateConfig("openapi_spec", text);
    } catch {
      setFileProblem(
        "That file could not be read. Choose a YAML or JSON text file.",
      );
    }
  };

  // One key per call: updateConfig replaces the config it was rendered with,
  // so the mode cannot be set in the same step. A draft is therefore only
  // offered while the mode is Recorded (canUseDraft), never switched to it.
  const useDraft = (document: string) => {
    setFileProblem("");
    updateConfig("openapi_spec", document);
  };

  const problem = fileProblem || openApiSpecProblem(spec);
  return (
    <Stack gap="xs">
      <Textarea
        label="OpenAPI document"
        description={OPENAPI_SPEC_HELP}
        placeholder={"openapi: 3.0.3\npaths:\n  /api/v1/orders:\n    get: ..."}
        value={spec}
        onChange={(e) => updateConfig("openapi_spec", e.currentTarget.value)}
        error={problem || undefined}
        autosize
        minRows={4}
        maxRows={14}
        styles={{
          input: { fontFamily: "var(--mantine-font-family-monospace)" },
        }}
      />
      <Group gap="xs">
        <FileButton accept=".yaml,.yml,.json" onChange={loadFile}>
          {(props) => (
            <Button {...props} variant="light" size="xs">
              Load from a file
            </Button>
          )}
        </FileButton>
        {spec && (
          <Button
            variant="subtle"
            color="red"
            size="xs"
            onClick={() => updateConfig("openapi_spec", "")}
          >
            Remove the document
          </Button>
        )}
      </Group>
      {showsModeSelect(spec, mode) ? (
        <Select
          label="A request outside the document is"
          description={OPENAPI_MODE_HELP}
          data={[
            {
              value: "record",
              label: "Recorded: forwarded and counted (default)",
            },
            {
              value: "enforce",
              label: "Refused: answered 403 before it reaches the backend",
            },
          ]}
          value={mode}
          onChange={(value) => updateConfig("openapi_mode", value || "record")}
          allowDeselect={false}
        />
      ) : (
        <Text size="xs" c="dimmed">
          No document, so requests on this route are not checked against an API
          description.
        </Text>
      )}
      {spec && auditOnly && mode === "enforce" && (
        <Alert color="yellow" variant="light">
          {OPENAPI_AUDIT_ONLY_NOTE}
        </Alert>
      )}
      <SchemaLearningFields
        config={config}
        updateConfig={updateConfig}
        onUse={useDraft}
      />
    </Stack>
  );
}
