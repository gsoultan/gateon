import { useState } from 'react'
import { Stack, Text, NumberInput, Button, Group, Table, Badge, Title, Paper, Alert } from '@mantine/core'
import { IconInfoCircle, IconRocket, IconCheck } from '@tabler/icons-react'
import { apiFetch, getApiErrorMessage } from '../hooks/useGateon'
import { notifications } from '@mantine/notifications'
import type { Service, Target } from '../types/gateon'

interface CanaryWizardProps {
  service: Service
  onSuccess: () => void
}

export function CanaryWizard({ service, onSuccess }: CanaryWizardProps) {
  const [duration, setDuration] = useState<number | string>(5)
  const [steps, setSteps] = useState<number | string>(10)
  const [targetWeights, setTargetWeights] = useState<Target[]>(
    service.weighted_targets.map(t => ({ ...t }))
  )
  const [loading, setLoading] = useState(false)

  const handleWeightChange = (url: string, weight: number | string) => {
    setTargetWeights(prev => prev.map(t => t.url === url ? { ...t, weight: Number(weight) } : t))
  }

  const startCanary = async () => {
    setLoading(true)
    try {
      const res = await apiFetch('/v1/services/canary', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          service_id: service.id,
          target_weights: targetWeights,
          duration_minutes: Number(duration),
          steps: Number(steps)
        })
      })
      if (!res.ok) throw new Error(await res.text())
      
      notifications.show({
        title: 'Canary Started',
        message: `Traffic shifting for ${service.id} has been initiated.`,
        color: 'green',
        icon: <IconCheck size={16} />
      })
      onSuccess()
    } catch (e) {
      notifications.show({
        title: 'Error',
        message: getApiErrorMessage(e),
        color: 'red'
      })
    } finally {
      setLoading(false)
    }
  }

  const totalWeight = targetWeights.reduce((acc, t) => acc + t.weight, 0)

  return (
    <Stack gap="lg">
      <Paper p="md" radius="md" withBorder bg="var(--mantine-color-blue-light)">
        <Group gap="xs">
          <IconInfoCircle size={20} color="var(--mantine-color-blue-filled)" />
          <Text size="sm" fw={600}>Automated Traffic Shifting</Text>
        </Group>
        <Text size="xs" c="dimmed" mt={4}>
          This wizard will gradually adjust the weights of your backend targets over the specified duration.
        </Text>
      </Paper>

      <Stack gap="xs">
        <Title order={5}>1. Configure Target Weights (Final State)</Title>
        <Table withColumnBorders variant="vertical">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Target URL</Table.Th>
              <Table.Th w={120}>Current</Table.Th>
              <Table.Th w={150}>Target Weight</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {service.weighted_targets.map((t, i) => (
              <Table.Tr key={i}>
                <Table.Td>
                  <Text size="xs" ff="monospace">{t.url}</Text>
                </Table.Td>
                <Table.Td>
                  <Badge variant="outline" size="sm">{t.weight}</Badge>
                </Table.Td>
                <Table.Td>
                  <NumberInput
                    size="xs"
                    min={0}
                    value={targetWeights.find(tw => tw.url === t.url)?.weight ?? 0}
                    onChange={(v) => handleWeightChange(t.url, v)}
                  />
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        <Group justify="flex-end">
           <Text size="xs" fw={700} c={totalWeight === 100 ? 'green' : 'orange'}>
             Total Weight: {totalWeight} {totalWeight !== 100 && '(Recommended: 100)'}
           </Text>
        </Group>
      </Stack>

      <Stack gap="xs">
        <Title order={5}>2. Deployment Schedule</Title>
        <Group grow>
          <NumberInput
            label="Total Duration (minutes)"
            min={1}
            value={duration}
            onChange={setDuration}
            radius="md"
          />
          <NumberInput
            label="Steps"
            description="Number of weight updates"
            min={1}
            value={steps}
            onChange={setSteps}
            radius="md"
          />
        </Group>
      </Stack>

      {totalWeight === 0 && (
        <Alert color="red" icon={<IconInfoCircle size={16} />}>
          Total weight cannot be zero.
        </Alert>
      )}

      <Button
        fullWidth
        size="md"
        radius="md"
        leftSection={<IconRocket size={20} />}
        onClick={startCanary}
        loading={loading}
        disabled={totalWeight === 0}
      >
        Start Canary Deployment
      </Button>
    </Stack>
  )
}
