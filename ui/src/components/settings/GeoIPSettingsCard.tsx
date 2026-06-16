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
import { apiFetch } from "../../hooks/useGateon";
import { COUNTRIES } from "../../utils/countries";
import { getCountryFlag } from "../../utils/format";

interface GeoIPStatus {
  exists: boolean;
  path: string;
  info: string;
}

interface GeoIPSettingsCardProps {
  config: GeoIPConfig;
  onChange: (config: GeoIPConfig) => void;
  onSave?: () => void;
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
      const resp = await apiFetch("/v1/geoip/update", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          maxmind_license_key: config.maxmind_license_key,
        }),
      });
      if (resp.ok) {
        notifications.show({
          title: "Success",
          message: "GeoIP database updated successfully",
          color: "green",
          icon: <IconCheck size={16} />,
        });
        onChange({ ...config, db_path: "geoip/GeoLite2-City.mmdb" });
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
          onChange({ ...config, asn_db_path: data.path });
        } else if (edition === "country") {
          onChange({ ...config, country_db_path: data.path });
        } else {
          onChange({ ...config, db_path: data.path });
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
            GeoIP database is missing. Trace points will not be shown on the map unless a database is provided or auto-update is configured with a license key.
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
              value={config.db_path || ""}
              onChange={(e) => onChange({ ...config, db_path: e.currentTarget.value })}
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
              value={config.asn_db_path || ""}
              onChange={(e) => onChange({ ...config, asn_db_path: e.currentTarget.value })}
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
              value={config.country_db_path || ""}
              onChange={(e) => onChange({ ...config, country_db_path: e.currentTarget.value })}
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
            checked={config.auto_update}
            onChange={(e) => onChange({ ...config, auto_update: e.currentTarget.checked })}
            disabled={!config.enabled || disabled}
          />

          <TextInput
            label="MaxMind License Key"
            placeholder="Your MaxMind license key"
            description="Required for automatic updates. Get one at maxmind.com"
            type="password"
            value={config.maxmind_license_key || ""}
            onChange={(e) => onChange({ ...config, maxmind_license_key: e.currentTarget.value })}
            disabled={!config.enabled || !config.auto_update || disabled}
          />

          <NumberInput
            label="Update Interval (Days)"
            description="How often to check for updates"
            min={1}
            max={365}
            value={config.update_interval_days || 30}
            onChange={(val) => onChange({ ...config, update_interval_days: Number(val) })}
            disabled={!config.enabled || !config.auto_update || disabled}
          />

          <Button
            leftSection={<IconDownload size={16} />}
            variant="light"
            onClick={handleUpdate}
            loading={updating}
            disabled={!config.enabled || !config.maxmind_license_key || disabled}
          >
            Update From MaxMind Now
          </Button>

          <Divider label="Country Geofencing" labelPosition="center" />

          <MultiSelect
            label="Blocked Countries"
            description="Select countries to block. Request from these countries will be denied."
            placeholder="Select countries"
            data={COUNTRIES}
            value={config.blocked_countries || []}
            onChange={(val) => onChange({ ...config, blocked_countries: val })}
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
            value={config.allowed_countries || []}
            onChange={(val) => onChange({ ...config, allowed_countries: val })}
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

          <Switch
            label="Enable XDP Geofencing"
            description="Perform geofencing at the kernel level using eBPF/XDP for higher performance"
            checked={config.xdp_geofencing}
            onChange={(e) => onChange({ ...config, xdp_geofencing: e.currentTarget.checked })}
            disabled={!config.enabled || disabled}
          />

          {onSave && (
            <Group justify="flex-end" mt="md">
              <Button onClick={onSave} loading={saving} size="sm" disabled={disabled}>
                Save GeoIP Settings
              </Button>
            </Group>
          )}
        </Stack>
      </Stack>
    </Card>
  );
}
