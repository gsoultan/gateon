// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Card, Title, Text, Stack, TextInput, NumberInput, Button, Group, Divider, Switch, Alert, Select, TagsInput } from "@mantine/core";
import { IconCheck, IconCpu, IconAlertTriangle } from "@tabler/icons-react";
import type { EbpfConfig } from "../../../types/gateon";
import { useNetworkInterfaces } from "../../../hooks/useNetworkInterfaces";

interface EbpfSettingsCardProps {
  ebpf: EbpfConfig | undefined;
  onChange: (ebpf: EbpfConfig) => void;
  disabled: boolean;
  canEdit: boolean;
  saving: boolean;
  onSave: () => void;
}

// Kernel offload: XDP/TC programs, port knocking and the kernel-level
// management allowlist. The interface list and attach status are polled only
// while this card is showing.
export function EbpfSettingsCard({ ebpf, onChange, disabled, canEdit, saving, onSave }: EbpfSettingsCardProps) {
  const { data: netInfo, isError: netInfoError } = useNetworkInterfaces();
  return (
    <Card withBorder shadow="sm" radius="md">
      <Stack gap="md">
        <Group justify="space-between">
          <Group gap="xs">
            <IconCpu color="var(--mantine-color-grape-filled)" />
            <Title order={3}>eBPF Offloading</Title>
          </Group>
          <Switch
            label="Enable eBPF"
            checked={ebpf?.enabled || false}
            onChange={(e) =>
              onChange({
                ...(ebpf || {}),
                enabled: e.currentTarget.checked,
              })
            }
            disabled={disabled}
          />
        </Group>
        <Text size="sm" c="dimmed">
          Offload traffic processing to the Linux kernel for maximum performance.
        </Text>

        {ebpf?.enabled && (
          <Stack gap="sm">
            {netInfoError || !netInfo?.interfaces?.length ? (
              // Fallback to free-text when the host interface list is
              // unavailable (e.g. air-gapped or restricted environments).
              <TextInput
                label="Network Interface"
                description="The network interface to attach eBPF programs to. Leave empty to use the one carrying the default route: ens5 on an EC2 host, eth0 inside a container."
                placeholder="default-route interface"
                value={ebpf.interface || ""}
                onChange={(e) => onChange({...ebpf!, interface: e.currentTarget.value})}
                disabled={disabled}
              />
            ) : (
              <Select
                label="Network Interface"
                description="The NIC to attach eBPF programs to. Left unset, the gateway uses the recommended one: the interface carrying the default route."
                placeholder={
                  netInfo.interfaces.find((i) => i.recommended)
                    ? `${netInfo.interfaces.find((i) => i.recommended)!.name} (recommended)`
                    : "Select interface"
                }
                data={netInfo.interfaces.map((i) => ({
                  value: i.name,
                  label: `${i.name}${i.recommended ? " ★" : ""} — ${
                    i.addrs.find((a) => a.includes(".")) || "no IPv4"
                  }${i.up ? "" : " (down)"}`,
                }))}
                value={ebpf.interface || null}
                onChange={(val) => onChange({...ebpf!, interface: val || ""})}
                searchable
                allowDeselect={false}
                disabled={disabled}
              />
            )}
            {netInfo?.ebpf?.attached ? (
              netInfo.ebpf.attachMode === "generic" ? (
                <Text size="xs" c="yellow">
                  <IconAlertTriangle size={12} style={{ verticalAlign: "middle" }} /> XDP attached to{" "}
                  {netInfo.ebpf.interface} in generic (SKB) mode — native driver mode is
                  unavailable on this NIC, so throughput is reduced. Drop metrics are live.
                </Text>
              ) : netInfo.ebpf.attachMode === "tcx" || netInfo.ebpf.attachMode === "clsact" ? (
                <Text size="xs" c="teal">
                  <IconCheck size={12} style={{ verticalAlign: "middle" }} /> Attached to{" "}
                  {netInfo.ebpf.interface} at the TC ingress hook ({netInfo.ebpf.attachMode}): packets are
                  dropped in the kernel before Gateon sees them, though after the NIC driver. Port knocking
                  and load balancing need native XDP and are not in force. Drop metrics are live.
                </Text>
              ) : (
                <Text size="xs" c="teal">
                  <IconCheck size={12} style={{ verticalAlign: "middle" }} /> XDP attached to{" "}
                  {netInfo.ebpf.interface} (native mode); eBPF drop metrics are live.
                </Text>
              )
            ) : netInfo?.ebpf?.enabled ? (
              <Alert color="red" variant="light" icon={<IconAlertTriangle size="1rem" />} title="eBPF not attached">
                <Text size="sm">
                  eBPF is enabled but no eBPF program is attached, so eBPF drop
                  metrics will read 0.
                  {netInfo.ebpf.loadError ? ` Reason: ${netInfo.ebpf.loadError}` : " Verify the selected interface exists and the gateway has CAP_BPF and CAP_NET_ADMIN."}
                </Text>
              </Alert>
            ) : null}
            <Switch
              label="XDP Rate Limiting"
              description="Drop floods in the kernel, before Gateon sees them"
              checked={ebpf.xdpRateLimit || false}
              onChange={(e) => onChange({...ebpf!, xdpRateLimit: e.currentTarget.checked})}
              disabled={disabled}
            />
            <Switch
              label="XDP IP Shunning"
              description="Automatically shun malicious IPs in the kernel (IPS)"
              checked={ebpf.xdpIpShunning || false}
              onChange={(e) => onChange({...ebpf!, xdpIpShunning: e.currentTarget.checked})}
              disabled={disabled}
            />
            <Switch
              label="TC Filtering"
              description="Attach at the TC ingress hook even with no XDP feature on. With one on, the gateway uses TC by itself wherever native XDP is unavailable."
              checked={ebpf.tcFiltering || false}
              onChange={(e) => onChange({...ebpf!, tcFiltering: e.currentTarget.checked})}
              disabled={disabled}
            />
            <Divider label="Port Knocking" labelPosition="left" />
            <Switch
              label="Enable Port Knocking"
              description="Hide management port until a secret sequence of knocks is received (XDP)."
              checked={ebpf.enableKnocking || false}
              onChange={(e) => onChange({...ebpf!, enableKnocking: e.currentTarget.checked})}
              disabled={disabled}
            />
            {ebpf.enableKnocking && (
              <>
                <NumberInput
                  label="Management Port to Hide"
                  placeholder="8080"
                  value={ebpf.mgmtPort || 8080}
                  onChange={(val) => onChange({...ebpf!, mgmtPort: Number(val)})}
                  disabled={disabled}
                />
                <TagsInput
                  label="Knocking Sequence (Ports)"
                  description="The sequence of ports to knock (e.g. 7000, 8000, 9000)."
                  placeholder="7000, 8000, 9000"
                  value={(ebpf.knockingSequence || []).map(String)}
                  onChange={(val) => onChange({...ebpf!, knockingSequence: val.map(Number)})}
                  disabled={disabled}
                />
              </>
            )}
            <Divider label="Management Allowlist" labelPosition="left" />
            <Switch
              label="Filter the management port in the kernel"
              description="Drop packets to the management port at the NIC unless the source is listed below."
              checked={ebpf.enableMgmtWhitelist || false}
              onChange={(e) => onChange({...ebpf!, enableMgmtWhitelist: e.currentTarget.checked})}
              disabled={disabled}
            />
            {ebpf.enableMgmtWhitelist && (
              <>
                <TagsInput
                  label="Allowed Addresses"
                  description="Bare IPv4 or IPv6 addresses; ranges cannot be expressed here and are ignored. A family with nothing listed is closed: list only IPv4 and no IPv6 address reaches the management port."
                  placeholder="203.0.113.7"
                  value={ebpf.mgmtWhitelistIps || []}
                  onChange={(val) => onChange({...ebpf!, mgmtWhitelistIps: val})}
                  disabled={disabled}
                />
                <Alert color="yellow" variant="light">
                  This is enforced before the packet reaches Gateon, so an address that is
                  not listed cannot reach the dashboard or the API at all. If the list ends
                  up empty, kernel filtering stays off rather than locking everyone out.
                </Alert>
              </>
            )}
            {canEdit && (
              <Group justify="flex-end" mt="md">
                <Button onClick={onSave} loading={saving} size="sm">
                  Save eBPF Settings
                </Button>
              </Group>
            )}
          </Stack>
        )}
      </Stack>
    </Card>
  );
}
