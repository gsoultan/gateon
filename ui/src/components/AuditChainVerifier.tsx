// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useState } from "react";
import { Alert, Button, Group, Stack, Text } from "@mantine/core";
import { IconShieldCheck } from "@tabler/icons-react";
import { api } from "../services/client";
import { describeVerification, verifyRefusalMessage, type VerifyOutcome } from "./auditVerify";

/** Entries the gateway checks per call; it caps the window at 5000. */
const WINDOW = 5000;

type State =
  | { kind: "idle" }
  | { kind: "running" }
  | { kind: "done"; outcome: VerifyOutcome; checked: number; nextAfterId: string }
  | { kind: "refused"; message: string };

/**
 * Verifies the audit log's HMAC chain, a window at a time (ADR 0050). The
 * chain was signed and never checked; this is the check. Each click checks
 * one bounded window, and "Continue" checks the next, so a long log is never
 * one unbounded request.
 */
export function AuditChainVerifier() {
  const [state, setState] = useState<State>({ kind: "idle" });

  const run = async (afterId: string, checkedBefore: number) => {
    setState({ kind: "running" });
    try {
      const res = await api.verifyAuditChain({ afterId, limit: WINDOW });
      const checked = checkedBefore + res.checked;
      setState({
        kind: "done",
        outcome: describeVerification(res, checked),
        checked,
        nextAfterId: res.nextAfterId,
      });
    } catch (err) {
      setState({ kind: "refused", message: verifyRefusalMessage(err) });
    }
  };

  return (
    <Stack gap="xs" align="flex-start">
      <Button
        variant="light"
        color="teal"
        leftSection={<IconShieldCheck size={18} />}
        loading={state.kind === "running"}
        onClick={() => void run("", 0)}
      >
        Verify integrity
      </Button>
      {state.kind === "done" && (
        <Alert color={state.outcome.color} title={state.outcome.title} role="status" w="100%">
          <Group justify="space-between" wrap="nowrap" align="flex-end">
            <Text size="sm">{state.outcome.message}</Text>
            {state.outcome.canContinue && (
              <Button size="xs" variant="light" onClick={() => void run(state.nextAfterId, state.checked)}>
                Continue
              </Button>
            )}
          </Group>
        </Alert>
      )}
      {state.kind === "refused" && (
        <Alert color="red" title="Not verified" role="alert" w="100%">
          {state.message}
        </Alert>
      )}
    </Stack>
  );
}
