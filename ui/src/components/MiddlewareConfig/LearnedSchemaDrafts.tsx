// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Alert, Button, Group, Loader, Stack, Text } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { apiFetch } from "../../hooks/api";
import { QueryError } from "../QueryError";
import { LEARNED_DRAFT_REVIEW_NOTE } from "./wafCopy";

/** What one learning route has drafted (schemalearn.Draft). */
export interface LearnedDraft {
  route: string;
  observed: number;
  operations: number;
  droppedOperations: number;
  droppedParameters: number;
  minSamples: number;
  document: string;
}

interface LearnedDrafts {
  drafts: LearnedDraft[];
  routesRejected: number;
  maxRoutes: number;
}

async function fetchLearnedDrafts(): Promise<LearnedDrafts> {
  const res = await apiFetch("/v1/waf/schema-drafts");
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
  const data = (await res.json()) as Partial<LearnedDrafts> | null;
  return {
    drafts: Array.isArray(data?.drafts) ? data.drafts : [],
    routesRejected: data?.routesRejected ?? 0,
    maxRoutes: data?.maxRoutes ?? 0,
  };
}

/** One line on where a route's draft stands. */
export function draftSummary(d: LearnedDraft): string {
  if (d.operations === 0) {
    return `${d.observed} requests seen. Nothing has been seen ${d.minSamples} times yet, so there is no draft.`;
  }
  const left =
    d.droppedOperations + d.droppedParameters > 0
      ? ` ${d.droppedOperations} requests and ${d.droppedParameters} parameters were left out: past a limit, or a name that cannot be used.`
      : "";
  return `${d.operations} operations drafted from ${d.observed} requests.${left}`;
}

interface LearnedDraftListProps extends LearnedDrafts {
  /** Whether the form already holds a document, which a draft must not replace unasked. */
  hasDocument: boolean;
  /** Whether the form refuses requests outside the document. A draft is never offered into that. */
  enforcing: boolean;
  onUse: (document: string) => void;
}

/** The drafts, once read. Split from the query so it can be rendered on its own. */
export function LearnedDraftList({
  drafts,
  routesRejected,
  maxRoutes,
  hasDocument,
  enforcing,
  onUse,
}: LearnedDraftListProps) {
  if (drafts.length === 0) {
    return (
      <Text size="xs" c="dimmed">
        No route is learning yet. Turn the switch on, save, and let the route
        take traffic.
      </Text>
    );
  }
  return (
    <Stack gap="xs">
      {drafts.map((d) => (
        <Group
          key={d.route}
          justify="space-between"
          wrap="nowrap"
          align="flex-start"
        >
          <Stack gap={0}>
            <Text size="sm" fw={500}>
              {d.route}
            </Text>
            <Text size="xs" c="dimmed">
              {draftSummary(d)}
            </Text>
          </Stack>
          {d.operations > 0 && (
            <Button
              variant="light"
              size="xs"
              disabled={hasDocument || enforcing}
              onClick={() => onUse(d.document)}
            >
              Use as the document
            </Button>
          )}
        </Group>
      ))}
      {hasDocument && (
        <Text size="xs" c="dimmed">
          This form already has a document. Remove it first to use a draft in
          its place.
        </Text>
      )}
      {!hasDocument && enforcing && (
        <Text size="xs" c="dimmed">
          Requests outside the document are set to be refused. Set that to
          Recorded first: a draft describes only the traffic seen so far, and
          refusing by it unread would refuse what was not seen.
        </Text>
      )}
      {routesRejected > 0 && (
        <Alert color="yellow" variant="light">
          {`${routesRejected} routes are not being learned: at most ${maxRoutes} routes learn at once.`}
        </Alert>
      )}
    </Stack>
  );
}

interface LearnedSchemaDraftsProps {
  hasDocument: boolean;
  enforcing: boolean;
  /** Puts a draft in the form's document field. Nothing is saved until the form is. */
  onUse: (document: string) => void;
}

// What the gateway has learned, read only when asked for: it is a look at
// live state, and an editor that is merely open should not ask for it.
export function LearnedSchemaDrafts(props: LearnedSchemaDraftsProps) {
  const [shown, setShown] = useState(false);
  if (!shown) {
    return (
      <Group>
        <Button variant="light" size="xs" onClick={() => setShown(true)}>
          Show what has been learned
        </Button>
      </Group>
    );
  }
  return <LearnedDraftsPanel {...props} />;
}

function LearnedDraftsPanel({
  hasDocument,
  enforcing,
  onUse,
}: LearnedSchemaDraftsProps) {
  const query = useQuery({
    queryKey: ["waf-schema-drafts"],
    queryFn: fetchLearnedDrafts,
    staleTime: 0,
  });
  return (
    <Stack gap="xs">
      {query.isLoading && (
        <Group gap="xs">
          <Loader size="xs" />
          <Text size="xs" c="dimmed">
            Reading what has been learned
          </Text>
        </Group>
      )}
      {query.isError && (
        <QueryError
          error={query.error}
          what="the learned drafts"
          onRetry={() => void query.refetch()}
        />
      )}
      {query.data && (
        <>
          <LearnedDraftList
            {...query.data}
            hasDocument={hasDocument}
            enforcing={enforcing}
            onUse={onUse}
          />
          <Text size="xs" c="dimmed">
            {LEARNED_DRAFT_REVIEW_NOTE}
          </Text>
          <Group>
            <Button
              variant="subtle"
              size="xs"
              loading={query.isFetching}
              onClick={() => void query.refetch()}
            >
              Read again
            </Button>
          </Group>
        </>
      )}
    </Stack>
  );
}
