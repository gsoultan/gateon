// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

import React from 'react';
import { Card, Title, Text, Stack, Group, Switch, TextInput, Badge, ThemeIcon, Box, SimpleGrid } from '@mantine/core';
import { IconBolt, IconCpu, IconBrain, IconAtom, IconScale } from '@tabler/icons-react';
import type { GlobalConfig } from '../../types/gateon';

interface TitanSettingsCardProps {
  config: GlobalConfig;
  onChange: (config: GlobalConfig) => void;
  disabled?: boolean;
}

export const TitanSettingsCard: React.FC<TitanSettingsCardProps> = ({ config, onChange, disabled }) => {
  const titan = config.titan || {
    enabled: false,
    enable_phantom: false,
    enable_ai_predictor: false,
    enable_pqc: false,
    enable_governor: false,
    aiModelPath: ''
  };

  const ebpf = config.ebpf || {
    enabled: false,
    xdp_cuckoo_filter: false,
    af_xdp_phantom: false,
    xdp_ja4_blocklist: false
  };

  const handleChange = (key: keyof typeof titan, value: any) => {
    onChange({
      ...config,
      titan: { ...titan, [key]: value }
    });
  };

  const handleEbpfChange = (key: keyof typeof ebpf, value: any) => {
    onChange({
      ...config,
      ebpf: { ...ebpf, [key]: value }
    });
  };

  return (
    <Card withBorder radius="lg" shadow="sm" p="lg">
      <Stack gap="md">
        <Group justify="space-between">
          <Group gap="xs">
            <ThemeIcon color="orange" variant="light" size="lg" radius="md">
              <IconBolt size={22} />
            </ThemeIcon>
            <Box>
              <Title order={4} fw={900}>TITAN Evolution</Title>
              <Text size="xs" c="dimmed">Next-generation performance and security optimizations</Text>
            </Box>
          </Group>
          <Switch
            checked={titan.enabled}
            onChange={(event) => handleChange('enabled', event.currentTarget.checked)}
            label={titan.enabled ? "TITAN ACTIVE" : "TITAN DISABLED"}
            color="orange"
            size="md"
            fw={700}
            disabled={disabled}
          />
        </Group>

        {titan.enabled && (
          <>
            <SimpleGrid cols={{ base: 1, md: 2 }} spacing="lg">
              <Card withBorder radius="md" p="md">
                <Stack gap="xs">
                  <Group gap="xs">
                    <IconCpu size={20} color="var(--mantine-color-blue-6)" />
                    <Text fw={700}>Phantom Core (Kernel Bypass)</Text>
                  </Group>
                  <Text size="xs" c="dimmed">
                    Enables io_uring and AF_XDP zero-copy proxying for sub-millisecond latency.
                  </Text>
                  <Switch
                    checked={titan.enable_phantom}
                    onChange={(event) => handleChange('enable_phantom', event.currentTarget.checked)}
                    label="Enable Phantom Proxying"
                    disabled={disabled}
                  />
                  <Switch
                    checked={ebpf.af_xdp_phantom}
                    onChange={(event) => handleEbpfChange('af_xdp_phantom', event.currentTarget.checked)}
                    label="AF_XDP Port Redirection"
                    disabled={disabled || !titan.enable_phantom}
                  />
                </Stack>
              </Card>

              <Card withBorder radius="md" p="md">
                <Stack gap="xs">
                  <Group gap="xs">
                    <IconBrain size={20} color="var(--mantine-color-indigo-6)" />
                    <Text fw={700}>Predictive AI Shield</Text>
                  </Group>
                  <Text size="xs" c="dimmed">
                    WASM-based Transformer for traffic prediction and RL-adaptive rate limiting.
                  </Text>
                  <Switch
                    checked={titan.enable_ai_predictor}
                    onChange={(event) => handleChange('enable_ai_predictor', event.currentTarget.checked)}
                    label="Enable AI Prediction"
                    disabled={disabled}
                  />
                  <TextInput
                    label="AI Model Path"
                    placeholder="/path/to/model.wasm"
                    value={titan.aiModelPath}
                    onChange={(event) => handleChange('aiModelPath', event.currentTarget.value)}
                    size="xs"
                    disabled={disabled || !titan.enable_ai_predictor}
                  />
                </Stack>
              </Card>

              <Card withBorder radius="md" p="md">
                <Stack gap="xs">
                  <Group gap="xs">
                    <IconAtom size={20} color="var(--mantine-color-teal-6)" />
                    <Text fw={700}>Quantum-Safe Defense</Text>
                  </Group>
                  <Text size="xs" c="dimmed">
                    Post-Quantum Cryptography (ML-KEM/ML-DSA) and Cuckoo Filter blocklists.
                  </Text>
                  <Switch
                    checked={titan.enable_pqc}
                    onChange={(event) => handleChange('enable_pqc', event.currentTarget.checked)}
                    label="Enable PQC Identity"
                    disabled={disabled}
                  />
                  <Switch
                    checked={ebpf.xdp_cuckoo_filter}
                    onChange={(event) => handleEbpfChange('xdp_cuckoo_filter', event.currentTarget.checked)}
                    label="eBPF Cuckoo Filter (O(1) blocking)"
                    disabled={disabled}
                  />
                  <Switch
                    checked={ebpf.xdp_ja4_blocklist}
                    onChange={(event) => handleEbpfChange('xdp_ja4_blocklist', event.currentTarget.checked)}
                    label="Kernel-Level JA4+ Hardening"
                    disabled={disabled}
                  />
                </Stack>
              </Card>

              <Card withBorder radius="md" p="md">
                <Stack gap="xs">
                  <Group gap="xs">
                    <IconScale size={20} color="var(--mantine-color-violet-6)" />
                    <Text fw={700}>Resource Governor</Text>
                  </Group>
                  <Text size="xs" c="dimmed">
                    Real-time pressure monitoring and adaptive scavenging for 2GB RAM stability.
                  </Text>
                  <Switch
                    checked={titan.enable_governor}
                    onChange={(event) => handleChange('enable_governor', event.currentTarget.checked)}
                    label="Enable Stability Governor"
                    disabled={disabled}
                  />
                  <Badge variant="light" color="violet" size="sm">
                    Thresholds: 80% RAM / 90% CPU
                  </Badge>
                </Stack>
              </Card>
            </SimpleGrid>
          </>
        )}
      </Stack>
    </Card>
  );
};
