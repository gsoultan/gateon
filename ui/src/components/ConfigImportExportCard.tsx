import { useState } from "react";
import { Card, Stack, Group, Button, Text, Paper, Alert, Title } from "@mantine/core";
import { IconDownload, IconUpload } from "@tabler/icons-react";
import { getApiBaseUrl } from "../store/useApiConfigStore";

interface ConfigImportExportCardProps {
  canImport?: boolean;
  canExport?: boolean;
}

export function ConfigImportExportCard({ canImport = true, canExport = true }: ConfigImportExportCardProps) {
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [dryRunDiff, setDryRunDiff] = useState<any>(null);

  const base = getApiBaseUrl();

  const getAuthHeaders = () => {
    try {
      const raw = localStorage.getItem("gateon-auth-storage");
      if (!raw) return {};
      const parsed = JSON.parse(raw);
      const token = parsed?.state?.token;
      return token ? { Authorization: `Bearer ${token}` } : {};
    } catch {
      return {};
    }
  };

  const handleExport = () => {
    const link = document.createElement("a");
    link.download = "gateon-config.json";
    link.style.display = "none";
    document.body.appendChild(link);
    fetch(`${base}/v1/config/export`, { headers: getAuthHeaders() })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.blob();
      })
      .then((blob) => {
        const u = URL.createObjectURL(blob);
        link.href = u;
        link.click();
        URL.revokeObjectURL(u);
      })
      .catch((e) => console.error("Export failed:", e))
      .finally(() => link.remove());
  };

  const handleImport = (dryRun = false) => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json";
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;
      setImporting(true);
      setImportError(null);
      setDryRunDiff(null);
      try {
        const body = await file.text();
        const res = await fetch(`${base}/v1/config/import${dryRun ? "?dry_run=true" : ""}`, {
          method: "POST",
          headers: { "Content-Type": "application/json", ...getAuthHeaders() },
          body,
        });
        const data = await res.json();
        if (!res.ok) {
          setImportError(data?.error || `HTTP ${res.status}`);
          return;
        }
        if (dryRun) {
          setDryRunDiff(data.diff);
          return;
        }
        if (data.errors?.length) {
          setImportError(data.errors.join("; "));
          return;
        }
        window.location.reload();
      } catch (err: unknown) {
        setImportError(err instanceof Error ? err.message : "Import failed");
      } finally {
        setImporting(false);
      }
    };
    input.click();
  };

  return (
    <Card withBorder padding="xl" radius="lg" shadow="xs">
      <Stack gap="md">
        <Group gap="md">
          <Paper p="xs" radius="md" bg="orange.6">
            <IconDownload size={20} color="white" />
          </Paper>
          <div>
            <Title order={4} fw={700}>
              Config Import / Export
            </Title>
            <Text c="dimmed" size="xs">
              Backup or restore routes, services, entrypoints, and middlewares.
            </Text>
          </div>
        </Group>
        {importError && (
          <Alert color="red" variant="light" withCloseButton onClose={() => setImportError(null)}>
            {importError}
          </Alert>
        )}
        <Group>
          {canExport && (
            <Button
              leftSection={<IconDownload size={16} />}
              variant="light"
              onClick={handleExport}
              radius="md"
            >
              Export Config
            </Button>
          )}
          {canImport && (
            <Group gap="xs">
              <Button
                leftSection={<IconUpload size={16} />}
                variant="light"
                color="orange"
                onClick={() => handleImport(false)}
                loading={importing && !dryRunDiff}
                radius="md"
              >
                Import Config
              </Button>
              <Button
                variant="subtle"
                color="gray"
                size="xs"
                onClick={() => handleImport(true)}
                loading={importing && !!dryRunDiff}
              >
                Dry Run Preview
              </Button>
            </Group>
          )}
        </Group>

        {dryRunDiff && (
          <Paper withBorder p="md" radius="md" bg="gray.0">
            <Stack gap="xs">
              <Group justify="space-between">
                <Text fw={600} size="sm">Import Preview (Dry Run)</Text>
                <Button size="compact-xs" variant="subtle" color="red" onClick={() => setDryRunDiff(null)}>Clear</Button>
              </Group>
              <Group gap="lg">
                <div>
                  <Text size="xs" fw={700} c="green">Created</Text>
                  <Text size="xs">Routes: {dryRunDiff.created?.routes?.length || 0}</Text>
                  <Text size="xs">Services: {dryRunDiff.created?.services?.length || 0}</Text>
                </div>
                <div>
                  <Text size="xs" fw={700} c="blue">Updated</Text>
                  <Text size="xs">Routes: {dryRunDiff.updated?.routes?.length || 0}</Text>
                  <Text size="xs">Services: {dryRunDiff.updated?.services?.length || 0}</Text>
                </div>
              </Group>
              <Text size="xs" c="dimmed" mt="xs">Click "Import Config" to apply these changes.</Text>
            </Stack>
          </Paper>
        )}
        <Text size="xs" c="dimmed">
          Export downloads gateon-config.json. Import merges the uploaded config (services first, then entrypoints, middlewares, routes).
        </Text>
      </Stack>
    </Card>
  );
}
