import React, { useState, useEffect } from 'react';
import {
  Title,
  Text,
  Card,
  Group,
  Badge,
  Button,
  Stack,
  Alert,
  Loader,
  ThemeIcon,
  Timeline,
  Divider,
  Code,
  Box,
} from '@mantine/core';
import {
  IconBrain,
  IconShieldCheck,
  IconBolt,
  IconActivity,
  IconAlertCircle,
  IconCheck,
  IconRefresh,
} from '@tabler/icons-react';
import { apiFetch } from '../../hooks/useGateon';

interface AIInsight {
  title: string;
  description: string;
  severity: string;
  category: string;
  recommendation: string;
  suggestedConfig?: string;
}

interface AIAnalysisResponse {
  summary: string;
  insights: AIInsight[];
}

export function AIAdvisoryTab() {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<AIAnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchInsights = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiFetch('/AnalyzeConfig', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ focus: 'security' }),
      });
      if (!res.ok) {
        throw new Error(await res.text());
      }
      const response = await res.json();
      setData(response);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to fetch AI insights';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchInsights();
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'red';
      case 'warning': return 'orange';
      case 'info': return 'blue';
      default: return 'gray';
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category.toLowerCase()) {
      case 'security': return <IconShieldCheck size={18} />;
      case 'performance': return <IconBolt size={18} />;
      case 'availability': return <IconActivity size={18} />;
      default: return <IconBrain size={18} />;
    }
  };

  return (
    <Stack gap="lg">
      <Group justify="space-between">
        <Stack gap={0}>
          <Title order={4}>AI Security Advisory</Title>
          <Text c="dimmed" size="sm">
            {data?.summary?.includes("Smart Engine")
              ? "Deterministic rule-based analysis of your gateway configuration (Local Mode)."
              : "LLM-powered analysis of your gateway configuration for security hardening."}
          </Text>
        </Stack>
        <Button
          leftSection={<IconRefresh size={16} />}
          variant="light"
          onClick={fetchInsights}
          loading={loading}
        >
          Re-analyze
        </Button>
      </Group>

      {loading && !data && (
        <Box py="xl">
          <Stack align="center">
            <Loader size="lg" />
            <Text size="sm">Gateon AI is analyzing your configuration...</Text>
          </Stack>
        </Box>
      )}

      {error && (
        <Alert icon={<IconAlertCircle size={16} />} title="Analysis Error" color="red">
          {error}
        </Alert>
      )}

      {data && (
        <>
          <Card withBorder shadow="sm" padding="lg" radius="md">
            <Group wrap="nowrap" align="flex-start">
              <ThemeIcon size={40} radius="md" variant="light" color="blue">
                <IconBrain size={24} />
              </ThemeIcon>
              <div>
                <Text fw={700} size="md">Executive Summary</Text>
                <Text size="sm" mt={4}>
                  {data.summary}
                </Text>
              </div>
            </Group>
          </Card>

          <Title order={5} mt="md">Proactive Recommendations</Title>

          <Timeline active={-1} bulletSize={32} lineWidth={2}>
            {data.insights?.map((insight, index) => (
              <Timeline.Item
                key={index}
                bullet={getCategoryIcon(insight.category)}
                title={
                  <Group gap="xs">
                    <Text fw={600} size="sm">{insight.title}</Text>
                    <Badge color={getSeverityColor(insight.severity)} variant="filled" size="xs">
                      {insight.severity}
                    </Badge>
                  </Group>
                }
              >
                <Card withBorder mt="xs" padding="sm" radius="md">
                  <Stack gap="xs">
                    <Text size="sm">{insight.description}</Text>
                    <Divider variant="dashed" />
                    <Group gap="xs" wrap="nowrap" align="flex-start">
                      <IconCheck size={16} color="var(--mantine-color-green-6)" style={{ marginTop: 2 }} />
                      <div>
                        <Text size="xs" fw={700} c="green">Recommendation:</Text>
                        <Text size="sm">{insight.recommendation}</Text>
                      </div>
                    </Group>
                    {insight.suggestedConfig && (
                      <Stack gap={4}>
                        <Text size="xs" fw={700} c="dimmed">Suggested Configuration:</Text>
                        <Code block color="gray.2">
                          {insight.suggestedConfig}
                        </Code>
                      </Stack>
                    )}
                  </Stack>
                </Card>
              </Timeline.Item>
            ))}
          </Timeline>
        </>
      )}

      {!loading && !data && !error && (
        <Text ta="center" c="dimmed" py="xl">
          No analysis data available. Click "Re-analyze" to start.
        </Text>
      )}
    </Stack>
  );
}
