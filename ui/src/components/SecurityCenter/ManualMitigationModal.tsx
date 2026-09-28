// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import React, { useState } from "react";
import {
  Modal,
  Stack,
  TextInput,
  Select,
  Textarea,
  Button,
  Group,
} from "@mantine/core";
import { IconShieldLock, IconFingerprint } from "@tabler/icons-react";
import { useMitigateThreat } from "../../hooks/useGateon";

interface ManualMitigationModalProps {
  opened: boolean;
  onClose: () => void;
}

export function ManualMitigationModal({ opened, onClose }: ManualMitigationModalProps) {
  const [source, setSource] = useState("");
  const [type, setType] = useState<string | null>("IP");
  const [category, setCategory] = useState<string | null>("manual");
  const [reason, setReason] = useState("");
  // A block holds until released ("0") unless a duration is chosen, after which
  // it lapses on its own (ADR 0037). Only an IP block honours this; a
  // fingerprint block carries its own TTL.
  const [duration, setDuration] = useState<string | null>("0");
  const mitigate = useMitigateThreat();

  const handleMitigate = async () => {
    try {
      await mitigate.mutateAsync({
        source,
        type: type || "IP",
        category: category || "manual",
        reason,
        durationSeconds: type === "IP" ? Number(duration ?? "0") : 0,
      });
      onClose();
      setSource("");
      setReason("");
      setDuration("0");
    } catch {
      // Error handled by hook
    }
  };

  return (
    <Modal
      opened={opened}
      onClose={onClose}
      title="Add Manual Mitigation"
      size="md"
      radius="md"
    >
      <Stack gap="md">
        <TextInput
          label="Source (IP or Fingerprint)"
          placeholder={type === "IP" ? "e.g., 203.0.113.7" : "fingerprint|203.0.113.7"}
          description={
            type === "IP"
              ? undefined
              : "A fingerprint names a browser build that every user of it shares, so it is blocked on one network: " +
                "name an address after it, and the block covers that address's /24 (or /64) only."
          }
          required
          value={source}
          onChange={(e) => setSource(e.currentTarget.value)}
          leftSection={type === "IP" ? <IconShieldLock size={16} /> : <IconFingerprint size={16} />}
        />
        <Select
          label="Type"
          data={[
            { value: "IP", label: "IP Address" },
            { value: "JA4+", label: "JA4+ Fingerprint" },
          ]}
          value={type}
          onChange={setType}
        />
        <Select
          label="Category"
          data={[
            { value: "manual", label: "Manual Override" },
            { value: "abuse", label: "Abuse / Spam" },
            { value: "injection", label: "Injection Attack" },
            { value: "scanner", label: "Vulnerability Scanner" },
            { value: "threatIntel", label: "Threat Intelligence" },
          ]}
          value={category}
          onChange={setCategory}
        />
        {type === "IP" && (
          <Select
            label="Duration"
            description="A bounded block lapses on its own with no operator; an open-ended block holds until released."
            data={[
              { value: "0", label: "Until released (no expiry)" },
              { value: "3600", label: "1 hour" },
              { value: "21600", label: "6 hours" },
              { value: "86400", label: "24 hours" },
              { value: "604800", label: "7 days" },
            ]}
            value={duration}
            onChange={setDuration}
          />
        )}
        <Textarea
          label="Reason"
          placeholder="Why are you mitigating this source?"
          value={reason}
          onChange={(e) => setReason(e.currentTarget.value)}
          minRows={3}
        />
        <Group justify="flex-end" mt="md">
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            color="red"
            onClick={handleMitigate}
            loading={mitigate.isPending}
            disabled={!source}
          >
            Block Source
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
