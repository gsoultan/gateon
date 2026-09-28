// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Text, Stack, TextInput, Button, Group, Divider, Switch, Alert, Select, Menu, Loader } from "@mantine/core";
import { IconInfoCircle, IconDownload, IconBox, IconChevronDown, IconShieldCheck, IconAdjustments, IconTrash } from "@tabler/icons-react";
import type { StatusResponse, WafConfig } from "../../../types/gateon";

interface ClamAVSectionProps {
  waf: WafConfig;
  onChange: (waf: WafConfig) => void;
  disabled: boolean;
  status: StatusResponse | undefined;
  installing: boolean;
  uninstalling: boolean;
  onInstall: (mode: number) => void;
  onUninstall: () => void;
}

// ClamAV for the WAF's malware detection: whether it is there, installing or
// removing it, and how the gateway reaches it.
export function ClamAVSection({
  waf,
  onChange,
  disabled,
  status,
  installing,
  uninstalling,
  onInstall,
  onUninstall,
}: ClamAVSectionProps) {
  return (
    <>
      <Divider label="ClamAV Anti-Malware" labelPosition="center" />
      {waf.malwareDetection && status && !status.clamavInstalled && (
        <Alert icon={<IconInfoCircle size="1rem" />} title="ClamAV Not Detected" color="red">
          <Stack gap="xs">
            <Text size="sm">
              Malware detection is enabled, but ClamAV is not installed or not running on the server.
              Please ensure ClamAV is installed locally or via Docker as configured below.
            </Text>
            <Group gap="sm">
              <Menu shadow="md" width={200} position="bottom-start">
                <Menu.Target>
                  <Button 
                    variant="white" 
                    size="xs" 
                    leftSection={installing ? <Loader size={14} color="blue" /> : <IconDownload size={14} />}
                    rightSection={<IconChevronDown size={14} />}
                    disabled={installing}
                  >
                    Install Now
                  </Button>
                </Menu.Target>

                <Menu.Dropdown>
                  <Menu.Label>Choose Installation Mode</Menu.Label>
                  <Menu.Item 
                    leftSection={<IconAdjustments size={14} />} 
                    onClick={() => onInstall(1)}
                  >
                    Local Installation
                  </Menu.Item>
                  <Menu.Item 
                    leftSection={<IconBox size={14} />} 
                    onClick={() => onInstall(2)}
                  >
                    Docker Container
                  </Menu.Item>
                </Menu.Dropdown>
              </Menu>
            </Group>
          </Stack>
        </Alert>
      )}
      {status && status.clamavInstalled && (
        <Alert icon={<IconShieldCheck size="1rem" />} title="ClamAV Installed" color="green">
          <Group justify="space-between" align="center">
            <Text size="sm">
              ClamAV is installed and managed by Gateon. You can remove it if it is no longer needed.
            </Text>
            <Button
              variant="white"
              color="red"
              size="xs"
              leftSection={uninstalling ? <Loader size={14} color="red" /> : <IconTrash size={14} />}
              disabled={uninstalling || disabled}
              onClick={onUninstall}
            >
              Uninstall
            </Button>
          </Group>
        </Alert>
      )}
      <Group grow>
        <Select
          label="Installation Mode"
          data={[
            { value: '1', label: 'Local Installation' },
            { value: '2', label: 'Docker Container' },
          ]}
          value={waf.clamav?.installationMode?.toString() || '2'}
          onChange={(val) => onChange({
            ...waf,
            clamav: {
              ...(waf.clamav || {}),
              installationMode: parseInt(val || '2')
            }
          })}
          disabled={disabled || !waf.malwareDetection}
        />
        <Switch
          label="Auto-Install/Manage"
          description="Let Gateon handle installation and lifecycle"
          checked={waf.clamav?.autoInstall}
          onChange={(e) => onChange({
            ...waf,
            clamav: {
              ...(waf.clamav || {}),
              autoInstall: e.currentTarget.checked
            }
          })}
          disabled={disabled || !waf.malwareDetection}
          mt="xl"
        />
      </Group>

      <Group grow>
        <TextInput
          label="ClamAV Address"
          description="Address of ClamAV daemon"
          placeholder="tcp://localhost:3310"
          value={waf.clamav?.clamavAddr || waf.clamavAddr || ""}
          onChange={(e) => onChange({
            ...waf,
            clamav: {
              ...(waf.clamav || {}),
              clamavAddr: e.currentTarget.value
            }
          })}
          disabled={disabled || !waf.malwareDetection}
        />
        <TextInput
          label="Full Scan Schedule"
          description="Cron expression for full system scans"
          placeholder="0 2 * * *"
          value={waf.clamav?.fullScanSchedule || ""}
          onChange={(e) => onChange({
            ...waf,
            clamav: {
              ...(waf.clamav || {}),
              fullScanSchedule: e.currentTarget.value
            }
          })}
          disabled={disabled || !waf.malwareDetection}
        />
      </Group>

      <Group grow>
        <Switch
          label="Low Resource Mode"
          description="Optimize for 1GB RAM / 2 Cores"
          checked={waf.clamav?.lowResourceMode}
          onChange={(e) => onChange({
            ...waf,
            clamav: {
              ...(waf.clamav || {}),
              lowResourceMode: e.currentTarget.checked
            }
          })}
          disabled={disabled || !waf.malwareDetection}
        />
        {waf.clamav?.installationMode === 2 && (
          <TextInput
            label="Docker Image"
            value={waf.clamav?.dockerImage || ""}
            placeholder="clamav/clamav:latest"
            onChange={(e) => onChange({
              ...waf,
              clamav: {
                ...(waf.clamav || {}),
                dockerImage: e.currentTarget.value
              }
            })}
            disabled={disabled || !waf.malwareDetection}
          />
        )}
      </Group>
    </>
  );
}
