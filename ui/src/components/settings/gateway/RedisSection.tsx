// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Text, Stack, TextInput, Group, Divider, Switch, Box } from "@mantine/core";
import type { RedisConfig } from "../../../types/gateon";
import { StoredSecretInput } from "../StoredSecretInput";

interface RedisSectionProps {
  redis: RedisConfig;
  onChange: (redis: RedisConfig) => void;
  disabled: boolean;
}

// The Redis connection shared by rate limiting, token revocation and the
// distributed cache.
export function RedisSection({ redis, onChange, disabled }: RedisSectionProps) {
  return (
    <Box>
      <Divider
        label={
          <Text size="xs" fw={800}>
            REDIS
          </Text>
        }
        labelPosition="left"
        mb="md"
      />
      <Stack gap="sm">
        <Switch
          label="Enable Redis (rate limiting, token revocation, and distributed cache)"
          checked={redis.enabled || false}
          disabled={disabled}
          onChange={(e) =>
            onChange({ ...redis, enabled: e.currentTarget.checked })
          }
          radius="md"
        />
        <Group grow>
          <TextInput
            label="Address"
            placeholder="localhost:6379"
            disabled={disabled || !redis.enabled}
            value={redis.addr || ""}
            onChange={(e) =>
              onChange({ ...redis, addr: e.currentTarget.value })
            }
            radius="md"
          />
          <StoredSecretInput
            label="Password"
            clearable
            disabled={disabled || !redis.enabled}
            value={redis.password}
            onChange={(password) =>
              onChange({ ...redis, password })
            }
          />
        </Group>
      </Stack>
    </Box>
  );
}
