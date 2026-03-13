import { useState } from "react";
import { Card, Stack, Group, Button, Text, Paper, Alert, Title } from "@mantine/core";
import { IconDownload, IconUpload } from "@tabler/icons-react";

interface ConfigImportExportCardProps {
  apiUrl: string;
}

export function ConfigImportExportCard({ apiUrl }: ConfigImportExportCardProps) {
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);

  const base = apiUrl.replace(/\/$/, "");

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

  const handleImport = () => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json";
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;
      setImporting(true);
      setImportError(null);
      try {
        const body = await file.text();
        const res = await fetch(`${base}/v1/config/import`, {
          method: "POST",
          headers: { "Content-Type": "application/json", ...getAuthHeaders() },
          body,
        });
        const data = await res.json();
        if (!res.ok) {
          setImportError(data?.error || `HTTP ${res.status}`);
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
          <Button
            leftSection={<IconDownload size={16} />}
            variant="light"
            onClick={handleExport}
            radius="md"
          >
            Export Config
          </Button>
          <Button
            leftSection={<IconUpload size={16} />}
            variant="light"
            color="orange"
            onClick={handleImport}
            loading={importing}
            radius="md"
          >
            Import Config
          </Button>
        </Group>
        <Text size="xs" c="dimmed">
          Export downloads gateon-config.json. Import merges the uploaded config (services first, then entrypoints, middlewares, routes).
        </Text>
      </Stack>
    </Card>
  );
}
