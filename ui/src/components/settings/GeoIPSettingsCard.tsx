// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import {
  Card,
  Title,
  Text,
  Stack,
  Switch,
  TextInput,
  NumberInput,
  Group,
  Button,
  Divider,
  Badge,
  Alert,
  FileButton,
  MultiSelect,
} from "@mantine/core";
import { IconDatabase, IconDownload, IconAlertCircle, IconCheck, IconUpload, IconWorld, IconLock, IconShieldCheck } from "@tabler/icons-react";
import { useEffect, useState } from "react";
import { notifications } from "@mantine/notifications";
import type { GeoIPConfig } from "../../types/gateon";
import type { GeoIPConfig as WireGeoIPConfig } from "../../services/gen/gateon/v1/global_pb";
import { apiFetch } from "../../hooks/useGateon";
import { COUNTRIES } from "../../utils/countries";
import { getCountryFlag } from "../../utils/format";
import { StoredSecretInput } from "./StoredSecretInput";

/** What the global country lists do now, from the gateway (ADR 0044). */
type GeofenceState = "off" | "active" | "block_list_inactive" | "allow_list_refusing_all";

interface GeoIPStatus {
  exists: boolean;
  path: string;
  info: string;
  geofence?: { state: GeofenceState; reason: string };
}

interface GeoIPSettingsCardProps {
  config: GeoIPConfig;
  onChange: (config: GeoIPConfig) => void;
  onSave?: () => void | Promise<void>;
  saving?: boolean;
  disabled?: boolean;
}

export function GeoIPSettingsCard({ config, onChange, onSave, saving, disabled }: GeoIPSettingsCardProps) {
  const [status, setStatus] = useState<GeoIPStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [uploading, setUploading] = useState(false);

  const fetchStatus = async () => {
    try {
      setLoading(true);
      const resp = await apiFetch("/v1/geoip/status");
      if (resp.ok) {
        const data = await resp.json();
        setStatus(data);
      }
    } catch (err) {
      console.error("Failed to fetch GeoIP status", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleUpdate = async () => {
    try {
      setUpdating(true);
      // The server decodes this body as GeoIPConfig, so its names are that
      // message's: typed from the generated one, a renamed field fails the build
      // rather than being dropped, as a snake_case tag once dropped this key.
      const body: Pick<WireGeoIPConfig, "maxmindLicenseKey"> = {
        maxmindLicenseKey: config.maxmindLicenseKey ?? "",
      };
      const resp = await apiFetch("/v1/geoip/update", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      });
      if (resp.ok) {
        notifications.show({
          title: "Success",
          message: "GeoIP database updated successfully",
          color: "green",
          icon: <IconCheck size={16} />,
        });
        onChange({ ...config, dbPath: "geoip/GeoLite2-City.mmdb" });
        fetchStatus();
      } else {
        const msg = await resp.text();
        notifications.show({
          title: "Update Failed",
          message: msg || "Failed to update GeoIP database",
          color: "red",
          icon: <IconAlertCircle size={16} />,
        });
      }
    } catch (err) {
      notifications.show({
        title: "Error",
        message: "Network error occurred during update",
        color: "red",
      });
    } finally {
      setUpdating(false);
    }
  };

  const handleUpload = (edition: "city" | "asn" | "country") => async (file: File | null) => {
    if (!file) return;

    try {
      setUploading(true);
      const formData = new FormData();
      formData.append("file", file);

      const resp = await apiFetch("/v1/geoip/upload", {
        method: "POST",
        body: formData,
      });

      if (resp.ok) {
        const data = await resp.json();
        notifications.show({
          title: "Success",
          message: "GeoIP database uploaded successfully",
          color: "green",
          icon: <IconCheck size={16} />,
        });
        if (edition === "asn") {
          onChange({ ...config, asnDbPath: data.path });
        } else if (edition === "country") {
          onChange({ ...config, countryDbPath: data.path });
        } else {
          onChange({ ...config, dbPath: data.path });
        }
        fetchStatus();
      } else {
        const msg = await resp.text();
        notifications.show({
          title: "Upload Failed",
          message: msg || "Failed to upload GeoIP database",
          color: "red",
          icon: <IconAlertCircle size={16} />,
        });
      }
    } catch (err) {
      notifications.show({
        title: "Error",
        message: "Network error occurred during upload",
        color: "red",
      });
    } finally {
      setUploading(false);
    }
  };

  return (
    <Card withBorder padding="lg" radius="md">
      <Stack gap="md">
        <Group justify="space-between">
          <Group>
            <IconDatabase size={24} />
            <div>
              <Title order={4}>GeoIP Configuration</Title>
              <Text size="sm" color="dimmed">
                Manage geographical intelligence database for IP resolution.
              </Text>
            </div>
          </Group>
          {status && (
            <Badge color={status.exists ? "green" : "red"} variant="light">
              {status.exists ? "Database Loaded" : "Not Loaded"}
            </Badge>
          )}
        </Group>

        <Divider />

        {status && status.exists && (
          <Alert color="blue" icon={<IconCheck size={16} />}>
            <Text size="sm"><b>Active Database:</b> {status.info}</Text>
            <Text size="xs" color="dimmed">Path: {status.path}</Text>
          </Alert>
        )}

        {!status?.exists && (
          <Alert color="orange" icon={<IconAlertCircle size={16} />}>
            GeoIP database is missing. Country geofencing cannot place any client in a country
            without one, so country lists cannot be saved, and trace points will not be shown on
            the map. Upload a MaxMind GeoLite2 City or Country database below, or set a licence key
            and update from MaxMind.
          </Alert>
        )}

        <Stack gap="sm">
          <Switch
            label="Enable GeoIP Resolution"
            description="Use GeoIP database to resolve IP addresses to geographical locations"
            checked={config.enabled}
            onChange={(e) => onChange({ ...config, enabled: e.currentTarget.checked })}
            disabled={disabled}
          />

          <Group align="flex-end">
            <TextInput
              label="Database Path"
              placeholder="e.g. geoip/GeoLite2-City.mmdb"
              description="Custom path to your MaxMind GeoLite2 City database"
              value={config.dbPath || ""}
              onChange={(e) => onChange({ ...config, dbPath: e.currentTarget.value })}
              disabled={!config.enabled || disabled}
              style={{ flex: 1 }}
            />
            <FileButton onChange={handleUpload("city")} accept=".mmdb">
              {(props) => (
                <Button 
                  {...props} 
                  variant="outline" 
                  leftSection={<IconUpload size={16} />} 
                  loading={uploading}
                  disabled={!config.enabled || disabled}
                >
                  Upload MMDB
                </Button>
              )}
            </FileButton>
          </Group>

          <Group align="flex-end">
            <TextInput
              label="ASN Database Path"
              placeholder="e.g. geoip/GeoLite2-ASN.mmdb"
              description="Path to your MaxMind GeoLite2 ASN database. Required to show the ASN of attack sources in Security Hub."
              value={config.asnDbPath || ""}
              onChange={(e) => onChange({ ...config, asnDbPath: e.currentTarget.value })}
              disabled={!config.enabled || disabled}
              style={{ flex: 1 }}
            />
            <FileButton onChange={handleUpload("asn")} accept=".mmdb">
              {(props) => (
                <Button
                  {...props}
                  variant="outline"
                  leftSection={<IconUpload size={16} />}
                  loading={uploading}
                  disabled={!config.enabled || disabled}
                >
                  Upload ASN MMDB
                </Button>
              )}
            </FileButton>
          </Group>

          <Group align="flex-end">
            <TextInput
              label="Country Database Path"
              placeholder="e.g. geoip/GeoLite2-Country.mmdb"
              description="Optional path to your MaxMind GeoLite2 Country database (geolocation fallback)."
              value={config.countryDbPath || ""}
              onChange={(e) => onChange({ ...config, countryDbPath: e.currentTarget.value })}
              disabled={!config.enabled || disabled}
              style={{ flex: 1 }}
            />
            <FileButton onChange={handleUpload("country")} accept=".mmdb">
              {(props) => (
                <Button
                  {...props}
                  variant="outline"
                  leftSection={<IconUpload size={16} />}
                  loading={uploading}
                  disabled={!config.enabled || disabled}
                >
                  Upload Country MMDB
                </Button>
              )}
            </FileButton>
          </Group>

          <Divider label="Auto Update" labelPosition="center" />

          <Switch
            label="Enable Automatic Updates"
            description="Periodically download the latest database from MaxMind"
            checked={config.autoUpdate}
            onChange={(e) => onChange({ ...config, autoUpdate: e.currentTarget.checked })}
            disabled={!config.enabled || disabled}
          />

          <StoredSecretInput
            label="MaxMind License Key"
            placeholder="Your MaxMind license key"
            description="Required for automatic updates. Get one at maxmind.com"
            clearable
            value={config.maxmindLicenseKey}
            onChange={(maxmindLicenseKey) => onChange({ ...config, maxmindLicenseKey })}
            disabled={!config.enabled || !config.autoUpdate || disabled}
          />

          <NumberInput
            label="Update Interval (Days)"
            description="How often to check for updates"
            min={1}
            max={365}
            value={config.updateIntervalDays || 30}
            onChange={(val) => onChange({ ...config, updateIntervalDays: Number(val) })}
            disabled={!config.enabled || !config.autoUpdate || disabled}
          />

          <Button
            leftSection={<IconDownload size={16} />}
            variant="light"
            onClick={handleUpdate}
            loading={updating}
            disabled={!config.enabled || !config.maxmindLicenseKey || disabled}
          >
            Update From MaxMind Now
          </Button>

          <Divider label="Country Geofencing" labelPosition="center" />

          <GeofenceAlert geofence={status?.geofence} />

          <MultiSelect
            label="Blocked Countries"
            description={
              status?.exists
                ? "Select countries to block. Requests from these countries will be denied."
                : "Select countries to block. Needs a GeoIP database: without one, no client can be placed in a country and a list cannot be saved."
            }
            placeholder="Select countries"
            data={COUNTRIES}
            value={config.blockedCountries || []}
            onChange={(val) => onChange({ ...config, blockedCountries: val })}
            disabled={!config.enabled || disabled}
            leftSection={<IconLock size={16} />}
            searchable
            nothingFoundMessage="No countries found"
            maxDropdownHeight={300}
            renderOption={({ option }) => (
              <Group gap="xs">
                <Text size="sm">{getCountryFlag(option.value)}</Text>
                <Text size="sm">{option.label}</Text>
                <Text size="xs" c="dimmed" ml="auto">{option.value}</Text>
              </Group>
            )}
            hidePickedOptions
          />

          <MultiSelect
            label="Allowed Countries"
            description="If set, ONLY these countries will be allowed. Leave empty to allow all (unless blocked above)."
            placeholder="Select countries"
            data={COUNTRIES}
            value={config.allowedCountries || []}
            onChange={(val) => onChange({ ...config, allowedCountries: val })}
            disabled={!config.enabled || disabled}
            leftSection={<IconWorld size={16} />}
            searchable
            nothingFoundMessage="No countries found"
            maxDropdownHeight={300}
            renderOption={({ option }) => (
              <Group gap="xs">
                <Text size="sm">{getCountryFlag(option.value)}</Text>
                <Text size="sm">{option.label}</Text>
                <Text size="xs" c="dimmed" ml="auto">{option.value}</Text>
              </Group>
            )}
            hidePickedOptions
          />

          {onSave && (
            <Group justify="flex-end" mt="md">
              <Button
                onClick={async () => {
                  await onSave();
                  // What the lists now do depends on what was saved.
                  await fetchStatus();
                }}
                loading={saving}
                size="sm"
                disabled={disabled}
              >
                Save GeoIP Settings
              </Button>
            </Group>
          )}
        </Stack>
      </Stack>
    </Card>
  );
}

// What the saved country lists do now, as the gateway reports it. A geofence
// with no database either refuses no one or refuses everyone, and saying
// "saved" there is how the control came to look in force when it was not.
function GeofenceAlert({ geofence }: { geofence: GeoIPStatus["geofence"] }) {
  if (!geofence || geofence.state === "off") return null;
  if (geofence.state === "active") {
    return (
      <Text size="xs" c="dimmed">
        Country lists are enforced on every HTTP entrypoint.
      </Text>
    );
  }
  const title =
    geofence.state === "allow_list_refusing_all"
      ? "Country geofencing refuses every request"
      : "Country block list is not enforced";
  return (
    <Alert color="red" icon={<IconAlertCircle size={16} />} title={title}>
      {geofence.reason}
    </Alert>
  );
}
