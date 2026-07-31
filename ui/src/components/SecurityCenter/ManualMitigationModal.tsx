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
  const mitigate = useMitigateThreat();

  const handleMitigate = async () => {
    try {
      await mitigate.mutateAsync({
        source,
        type: type || "IP",
        category: category || "manual",
        reason,
      });
      onClose();
      setSource("");
      setReason("");
    } catch (err) {
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
          placeholder="e.g., 1.2.3.4 or ja4_fingerprint..."
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
            { value: "threat_intel", label: "Threat Intelligence" },
          ]}
          value={category}
          onChange={setCategory}
        />
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
