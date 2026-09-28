// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Card, Title, Text, Stack, NumberInput, Button, Group, Switch } from "@mantine/core";
import { IconActivity } from "@tabler/icons-react";
import type { AnomalyDetectionConfig } from "../../../types/gateon";

interface AnomalyDetectionCardProps {
  anomalyDetection: AnomalyDetectionConfig | undefined;
  onChange: (anomalyDetection: AnomalyDetectionConfig) => void;
  disabled: boolean;
  canEdit: boolean;
  saving: boolean;
  onSave: () => void;
}

// In-process detection of unusual traffic patterns.
export function AnomalyDetectionCard({ anomalyDetection, onChange, disabled, canEdit, saving, onSave }: AnomalyDetectionCardProps) {
  return (
    <Card withBorder shadow="sm" radius="md">
      <Stack gap="md">
        <Group justify="space-between">
          <Group gap="xs">
            <IconActivity color="var(--mantine-color-orange-filled)" />
            <Title order={3}>Anomaly Detection</Title>
          </Group>
          <Switch
            label="Enable AI Detection"
            checked={anomalyDetection?.enabled || false}
            onChange={(e) =>
              onChange({
                ...(anomalyDetection || {
                  checkIntervalSeconds: 60,
                  sensitivity: 0.5,
                }),
                enabled: e.currentTarget.checked,
              })
            }
            disabled={disabled}
          />
        </Group>
        <Text size="sm" c="dimmed">
          Monitor traffic patterns in-process and detect anomalies in real-time.
        </Text>

        {anomalyDetection?.enabled && (
          <Stack gap="sm">
            <Group grow>
              <NumberInput
                label="Check Interval (s)"
                min={10}
                value={anomalyDetection.checkIntervalSeconds}
                onChange={(v) => onChange({...anomalyDetection!, checkIntervalSeconds: Number(v)})}
                disabled={disabled}
              />
              <NumberInput
                label="Sensitivity"
                decimalScale={2}
                step={0.1}
                min={0}
                max={1}
                value={anomalyDetection.sensitivity}
                onChange={(v) => onChange({...anomalyDetection!, sensitivity: Number(v)})}
                disabled={disabled}
              />
              <NumberInput
                label="Security Threat Threshold"
                decimalScale={1}
                step={1}
                min={1}
                max={100}
                value={anomalyDetection.securityThreatThreshold || 15.0}
                onChange={(v) => onChange({...anomalyDetection!, securityThreatThreshold: Number(v)})}
                disabled={disabled}
              />
            </Group>
            {canEdit && (
              <Group justify="flex-end" mt="md">
                <Button onClick={onSave} loading={saving} size="sm">
                  Save Anomaly Settings
                </Button>
              </Group>
            )}
          </Stack>
        )}
      </Stack>
    </Card>
  );
}
