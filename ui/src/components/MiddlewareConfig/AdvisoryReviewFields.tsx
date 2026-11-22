// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Alert, Group, Loader, NumberInput, Stack, Switch, Text } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";

import { apiFetch } from "../../hooks/api";
import { QueryError } from "../QueryError";
import { ADVISORY_NO_WORKER_NOTE, ADVISORY_REVIEW_HELP, ADVISORY_SAMPLE_HELP } from "./wafCopy";

/** Where the exchange with the advisory worker stands (advisory.Status). */
export interface AdvisoryStatus {
  configured: boolean;
  worker: string;
  mode: string;
  queueCapacity: number;
  queued: number;
  offered: number;
  dropped: number;
  sent: number;
  failed: number;
  flagged: number;
  lastContact: number;
  lastError: string;
}

async function fetchAdvisoryStatus(): Promise<AdvisoryStatus> {
  const res = await apiFetch("/v1/waf/advisory");
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
  const data = (await res.json()) as Partial<AdvisoryStatus> | null;
  return {
    configured: data?.configured === true,
    worker: data?.worker ?? "",
    mode: data?.mode ?? "",
    queueCapacity: data?.queueCapacity ?? 0,
    queued: data?.queued ?? 0,
    offered: data?.offered ?? 0,
    dropped: data?.dropped ?? 0,
    sent: data?.sent ?? 0,
    failed: data?.failed ?? 0,
    flagged: data?.flagged ?? 0,
    lastContact: data?.lastContact ?? 0,
    lastError: data?.lastError ?? "",
  };
}

/** What a verdict does on this gateway, in a sentence. */
export function advisoryModeSummary(mode: string): string {
  return mode === "reputation"
    ? "What it flags is listed in the Security Hub and counts against the client's reputation."
    : "What it flags is listed in the Security Hub and held against nobody.";
}

/** What became of the samples, in a sentence. */
export function advisoryCountsSummary(s: AdvisoryStatus): string {
  if (s.offered === 0) {
    return "No request has been sent yet. Save, and let the route take traffic.";
  }
  const lost: string[] = [];
  if (s.dropped > 0) lost.push(`${s.dropped} were left out because the queue of ${s.queueCapacity} was full`);
  if (s.failed > 0) lost.push(`${s.failed} were lost because the worker did not answer`);
  const tail = lost.length > 0 ? ` ${lost.join(", and ")}.` : "";
  return `${s.sent} requests judged across all routes, ${s.flagged} flagged.${tail}`;
}

/** The status, once read. Split from the query so it can be rendered on its own. */
export function AdvisoryStatusView({ status }: { status: AdvisoryStatus }) {
  if (!status.configured) {
    return (
      <Alert color="yellow" variant="light">
        {ADVISORY_NO_WORKER_NOTE}
      </Alert>
    );
  }
  return (
    <Stack gap="xs">
      <Text size="xs" c="dimmed">
        {`The worker is ${status.worker}. ${advisoryModeSummary(status.mode)}`}
      </Text>
      <Text size="xs" c="dimmed">
        {advisoryCountsSummary(status)}
      </Text>
      {status.lastError !== "" && (
        <Alert color="yellow" variant="light">
          {`The worker is not answering, and requests sent to it are lost until it does: ${status.lastError}`}
        </Alert>
      )}
    </Stack>
  );
}

// Read as soon as the switch is on: whether the gateway has a worker at all
// decides whether the switch does anything, and the form has to say so before
// it is saved.
function AdvisoryStatusPanel() {
  const query = useQuery({
    queryKey: ["waf-advisory-status"],
    queryFn: fetchAdvisoryStatus,
    staleTime: 0,
  });
  return (
    <Stack gap="xs">
      {query.isLoading && (
        <Group gap="xs">
          <Loader size="xs" />
          <Text size="xs" c="dimmed">
            Checking for an advisory worker
          </Text>
        </Group>
      )}
      {query.isError && (
        <QueryError error={query.error} what="the advisory worker's status" onRetry={() => void query.refetch()} />
      )}
      {query.data && <AdvisoryStatusView status={query.data} />}
    </Stack>
  );
}

interface AdvisoryReviewFieldsProps {
  config: Record<string, string>;
  updateConfig: (key: string, value: string) => void;
}

/** The route WAF's second-opinion settings (ADR 0104). */
export function AdvisoryReviewFields({ config, updateConfig }: AdvisoryReviewFieldsProps) {
  const on = config.advisory_review === "true";
  return (
    <>
      <Switch
        label="Ask the advisory worker about forwarded requests"
        description={ADVISORY_REVIEW_HELP}
        checked={on}
        onChange={(e) => updateConfig("advisory_review", e.currentTarget.checked ? "true" : "false")}
      />
      {on && (
        <>
          <NumberInput
            label="Also Ask About Ordinary Requests"
            description={ADVISORY_SAMPLE_HELP}
            placeholder="Off"
            value={parseInt(config.advisory_sample_rate) || ""}
            onChange={(val) => updateConfig("advisory_sample_rate", (Number(val) || 0).toString())}
            min={0}
            allowDecimal={false}
          />
          <AdvisoryStatusPanel />
        </>
      )}
    </>
  );
}
