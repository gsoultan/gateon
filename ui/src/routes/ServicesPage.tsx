// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Fragment, useCallback, useState } from 'react'
import { Card, Text, Stack, Group, Button,  Table, ActionIcon, Badge, TextInput, Center, Box, Menu, Tooltip, Paper, SimpleGrid, Pagination, Skeleton } from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { IconPlus, IconServer, IconSearch, IconDotsVertical, IconEdit, IconTrash, IconExternalLink, IconActivity, IconChevronDown, IconChevronRight, IconRocket } from '@tabler/icons-react'
import { useServices, apiFetch, getApiErrorMessage } from '../hooks/useGateon'
import { usePermissions } from '../hooks/usePermissions'
import { useIsMobile } from '../hooks/useMobile'
import { ServiceForm } from '../components/ServiceForm'
import { CanaryWizard } from '../components/CanaryWizard'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { notifications } from '@mantine/notifications'
import { QueryError } from "../components/QueryError";
import { ConfirmDeleteModal } from "../components/ConfirmDelete";
import { FormDrawer, PageHeader, useCreateFromLink } from "../components/layout";
import { StatusChip, circuitState, ratioState } from "../components/status";
import { useAllRouteStats } from "../hooks/useRouteStats";
import { CircuitEvents } from "../components/Services/CircuitEvents";
import type { TargetStats } from "../types/gateon";

export default function ServicesPage() {
  const { canWrite } = usePermissions()
  const isMobile = useIsMobile()
  const [opened, { open, close }] = useDisclosure(false)
  const [canaryOpened, { open: openCanary, close: closeCanary }] = useDisclosure(false)
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set())
  const pageSize = 10

  const toggleExpand = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  // Every route's target stats, keyed by target URL: a service's targets are
  // reached through the routes that name it, and the circuit the gateway keeps
  // per target is what the Circuit Breaker page used to show on its own.
  const { data: routeStats } = useAllRouteStats()
  const statsByUrl = new Map<string, TargetStats>()
  for (const targets of Object.values(routeStats ?? {})) for (const t of targets) statsByUrl.set(t.url, t)

  const { data, isLoading, isError, error, refetch } = useServices({
    page: page - 1,
    pageSize: pageSize,
    search: search,
  })
  const queryClient = useQueryClient()

  // Deleting used to happen on the menu click itself; it waits for a
  // confirmation that names the service now.
  const [pendingDelete, setPendingDelete] = useState<{ id: string; name?: string } | null>(null)

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiFetch(`/v1/services/${encodeURIComponent(id)}`, { method: 'DELETE' })
      if (!res.ok) throw new Error(await res.text())
      return true
    },
    onSuccess: () => {
      setPendingDelete(null)
      queryClient.invalidateQueries({ queryKey: ['services'] })
      notifications.show({
        title: 'Service Deleted',
        message: 'The service has been successfully removed.',
        color: 'green'
      })
    },
    onError: (err: unknown) => {
      notifications.show({
        title: 'Error',
        message: getApiErrorMessage(err),
        color: 'red'
      })
    }
  })

  const [editingService, setEditingService] = useState<any>(null)
  const [canaryService, setCanaryService] = useState<any>(null)

  const handleEdit = (service: any) => {
    setEditingService(service)
    open()
  }

  const handleCanary = (service: any) => {
    setCanaryService(service)
    openCanary()
  }

  const handleCreate = useCallback(() => {
    setEditingService(null)
    open()
  }, [open])
  useCreateFromLink(canWrite, handleCreate)

  const services = data?.services || []
  const totalCount = data?.totalCount || 0

  return (
    <Stack gap="lg">
      <PageHeader
        title="Services"
        description="Define HTTP & gRPC backend targets and load balancing policies."
        actions={
          canWrite && (
            <Button leftSection={<IconPlus size={18} />} onClick={handleCreate}>Create Service</Button>
          )
        }
      />

      <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="md">
        <Paper p="md" radius="lg" withBorder>
          <Group>
            <ActionIcon variant="light" color="blue" size="lg" radius="md">
              <IconServer size={20} />
            </ActionIcon>
            <div>
              <Text size="xs" c="dimmed" fw={800} style={{ textTransform: 'uppercase', letterSpacing: 1 }}>Total Services</Text>
              <Text fw={700} size="xl">{totalCount}</Text>
            </div>
          </Group>
        </Paper>
        <Paper p="md" radius="lg" withBorder>
          <Group>
            <ActionIcon variant="light" color="teal" size="lg" radius="md">
              <IconActivity size={20} />
            </ActionIcon>
            <div>
              <Text size="xs" c="dimmed" fw={800} style={{ textTransform: 'uppercase', letterSpacing: 1 }}>Active Targets</Text>
              <Text fw={700} size="xl">
                {data?.services?.reduce((acc, s) => acc + s.weightedTargets.length, 0) || 0}
              </Text>
            </div>
          </Group>
        </Paper>
      </SimpleGrid>

      <Card shadow="xs" padding="lg" radius="lg" withBorder>
        <Stack gap="md">
          <TextInput 
            placeholder="Search services..." 
            leftSection={<IconSearch size={16} />} 
            value={search} 
            onChange={(e) => {
              setSearch(e.currentTarget.value)
              setPage(1)
            }}
            size="xs"
            w={isMobile ? '100%' : 300}
          />

          <Box style={{ overflowX: isMobile ? undefined : 'auto' }}>
            {isError ? (
              <QueryError error={error} what="services" onRetry={() => refetch()} />
            ) : isLoading ? (
              <Stack gap="md">
                {[...Array(5)].map((_, i) => (
                  <Card key={i} withBorder radius="md" p="md">
                    <Group justify="space-between">
                      <Stack gap={4} style={{ flex: 1 }}>
                        <Skeleton height={20} width="40%" />
                        <Skeleton height={14} width="25%" />
                      </Stack>
                      <Group gap="xs">
                        <Skeleton height={24} width={80} radius="xl" />
                        <Skeleton height={28} width={28} radius="sm" />
                      </Group>
                    </Group>
                  </Card>
                ))}
              </Stack>
            ) : isMobile ? (
              <Stack gap="md">
                {services.length === 0 && !isLoading && (
                  <Center py={48}>
                    <Stack align="center" gap="sm">
                      <IconServer size={48} stroke={1.2} style={{ opacity: 0.4 }} />
                      <Text c="dimmed" ta="center">No services found.</Text>
                    </Stack>
                  </Center>
                )}
                {services.map(s => (
                  <Card key={s.id} withBorder radius="md" p="md">
                    <Stack gap="xs">
                      <Group justify="space-between" align="flex-start">
                        <Stack gap={2}>
                          <Text fw={700} size="sm" c="indigo.3">{s.id}</Text>
                          <Text size="xs" c="dimmed">{s.name}</Text>
                        </Stack>
                        <Group gap={4}>
                          <Badge size="xs" variant="outline">{(s.loadBalancerPolicy || "").replace(/_/g, ' ')}</Badge>
                          {canWrite && (
                            <Menu shadow="md" position="bottom-end">
                              <Menu.Target>
                                <ActionIcon variant="subtle" color="gray" aria-label={`Manage service ${s.name || s.id}`}><IconDotsVertical size={16} /></ActionIcon>
                              </Menu.Target>
                              <Menu.Dropdown>
                                <Menu.Item leftSection={<IconEdit size={14} />} onClick={() => handleEdit(s)}>Edit</Menu.Item>
                                <Menu.Item leftSection={<IconRocket size={14} />} color="blue" onClick={() => handleCanary(s)}>Canary Deployment</Menu.Item>
                                <Menu.Divider />
                                <Menu.Item leftSection={<IconTrash size={14} />} color="red" onClick={() => setPendingDelete(s)}>Delete</Menu.Item>
                              </Menu.Dropdown>
                            </Menu>
                          )}
                        </Group>
                      </Group>
                      
                      <Box>
                        <Text size="xs" c="dimmed" fw={700} style={{ textTransform: 'uppercase' }}>Targets ({s.weightedTargets.length})</Text>
                        <Stack gap={4} mt={4}>
                          {s.weightedTargets.slice(0, 3).map((t, i) => (
                            <Group key={i} gap="xs" wrap="nowrap">
                              <Text size="xs" ff="monospace" truncate style={{ flex: 1 }}>{t.url}</Text>
                              <Badge size="xs" variant="light">{t.weight}</Badge>
                            </Group>
                          ))}
                          {s.weightedTargets.length > 3 && (
                            <Text size="xs" c="dimmed">+{s.weightedTargets.length - 3} more...</Text>
                          )}
                        </Stack>
                      </Box>
                    </Stack>
                  </Card>
                ))}
              </Stack>
            ) : (
              <Table verticalSpacing="md" highlightOnHover layout="fixed">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th w={40} />
                  <Table.Th>Service</Table.Th>
                  <Table.Th>Targets</Table.Th>
                  <Table.Th>Policy</Table.Th>
                  <Table.Th>Status</Table.Th>
                  <Table.Th w={80}>Actions</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {services.length === 0 && !isLoading && (
                  <Table.Tr>
                    <Table.Td colSpan={6}>
                      <Center py={48}>
                        <Stack align="center" gap="sm">
                          <IconServer size={48} stroke={1.2} style={{ opacity: 0.4 }} />
                          <Text c="dimmed" ta="center" maw={360}>
                            No services yet. Create a service to define HTTP or gRPC backend targets and load balancing.
                          </Text>
                          {canWrite && (
                            <Button variant="light" size="sm" leftSection={<IconPlus size={16} />} onClick={handleCreate}>
                              Create your first service
                            </Button>
                          )}
                        </Stack>
                      </Center>
                    </Table.Td>
                  </Table.Tr>
                )}
                {services.map(s => {
                  const targets = s.weightedTargets || (s as any).weighted_targets || [];
                  const isExpanded = expandedIds.has(s.id);
                  const firstTarget = targets[0]?.url || '';
                  const hasMore = targets.length > 1;
                  const known = targets.map((t: { url: string }) => statsByUrl.get(t.url)).filter((t): t is TargetStats => !!t);
                  const up = known.filter((t) => t.alive && t.circuitState !== 'open').length;
                  const health = known.length === 0 ? ratioState(undefined, undefined) : ratioState(up, known.length);
                  return (
                    <Fragment key={s.id}>
                      <Table.Tr>
                        <Table.Td>
                          {targets.length > 0 && (
                            <ActionIcon
                              variant="subtle"
                              size="sm"
                              onClick={() => toggleExpand(s.id)}
                              aria-label={isExpanded ? 'Hide targets' : 'Show targets'}
                            >
                              {isExpanded ? <IconChevronDown size={14} /> : <IconChevronRight size={14} />}
                            </ActionIcon>
                          )}
                        </Table.Td>
                        <Table.Td>
                          <Stack gap={2}>
                            <Text fw={700} size="sm" c="indigo.3">{s.id}</Text>
                            <Text size="xs" c="dimmed">{s.name}</Text>
                          </Stack>
                        </Table.Td>
                        <Table.Td>
                          <Stack gap={4}>
                            <Tooltip label={firstTarget} multiline maw={320}>
                              <Text size="xs" truncate style={{ maxWidth: 220 }} c="dimmed">
                                {firstTarget || '—'}
                              </Text>
                            </Tooltip>
                            {hasMore && (
                              <Badge variant="light" color="blue" size="xs">
                                +{targets.length - 1} more
                              </Badge>
                            )}
                          </Stack>
                        </Table.Td>
                        <Table.Td>
                          <Text size="xs" fw={600} tt="capitalize">
                            {(s.loadBalancerPolicy || "").replace(/_/g, ' ')}
                          </Text>
                        </Table.Td>
                        <Table.Td>
                          <StatusChip
                            state={health.state}
                            label={health.label}
                            reason={known.length === 0 ? 'No route sends traffic here yet' : `${up} of ${known.length} targets taking traffic`}
                          />
                        </Table.Td>
                        <Table.Td>
                          {canWrite && (
                            <Menu shadow="md" position="bottom-end" transitionProps={{ transition: 'pop-top-right' }}>
                              <Menu.Target>
                                <ActionIcon variant="subtle" color="gray" aria-label={`Manage service ${s.name || s.id}`}><IconDotsVertical size={16} /></ActionIcon>
                              </Menu.Target>
                              <Menu.Dropdown>
                                <Menu.Label>Actions</Menu.Label>
                                <Menu.Item leftSection={<IconEdit size={14} />} onClick={() => handleEdit(s)}>Edit</Menu.Item>
                                <Menu.Item leftSection={<IconRocket size={14} />} color="blue" onClick={() => handleCanary(s)}>Canary Deployment</Menu.Item>
                                <Menu.Divider />
                                <Menu.Item leftSection={<IconTrash size={14} />} color="red" onClick={() => setPendingDelete(s)}>Delete</Menu.Item>
                              </Menu.Dropdown>
                            </Menu>
                          )}
                        </Table.Td>
                      </Table.Tr>
                      {isExpanded && (
                        <Table.Tr>
                          <Table.Td colSpan={6} py="xs" style={{ backgroundColor: 'var(--mantine-color-default-hover)' }}>
                            <Stack gap={6} pl="md">
                              <Text size="xs" fw={600} c="dimmed">Targets</Text>
                              {targets.map((t: { url: string; weight?: number }, i: number) => {
                                const st = statsByUrl.get(t.url);
                                const circuit = st ? (st.alive || st.circuitState === 'open' ? circuitState(st.circuitState ?? 'closed') : { state: 'down' as const, label: 'Down' }) : { state: 'unknown' as const, label: 'Unknown' };
                                return (
                                  <Group key={i} gap="sm" wrap="nowrap">
                                    <Text size="xs" ff="monospace" c="dimmed" style={{ minWidth: 0 }} truncate>
                                      {t.url}
                                    </Text>
                                    <Badge variant="outline" size="xs">weight {t.weight}</Badge>
                                    <StatusChip state={circuit.state} label={circuit.label} size="xs" reason={st ? `${st.requestCount} requests, ${st.errorCount} errors, ${st.activeConn} open` : 'No traffic has reached this target through a route yet'} />
                                  </Group>
                                );
                              })}
                            </Stack>
                          </Table.Td>
                        </Table.Tr>
                      )}
                    </Fragment>
                  )
                })}
              </Table.Tbody>
            </Table>
            )}
          </Box>

          {totalCount > pageSize && (
            <Group justify="center" mt="md">
              <Pagination
                total={Math.ceil(totalCount / pageSize)}
                value={page}
                onChange={setPage}
                size="sm"
              />
            </Group>
          )}
        </Stack>
      </Card>

      <CircuitEvents />

      <ConfirmDeleteModal
        target={pendingDelete ? { kind: 'service', name: pendingDelete.name || pendingDelete.id, id: pendingDelete.id } : null}
        consequence="Routes that send traffic to it are left without an upstream."
        loading={deleteMutation.isPending}
        onCancel={() => setPendingDelete(null)}
        onConfirm={() => pendingDelete && deleteMutation.mutate(pendingDelete.id)}
      />

      <FormDrawer
        opened={opened}
        onClose={close}
        title={editingService ? 'Edit Service' : 'Create New Service'}
        width="wide"
      >
        <ServiceForm 
          onSuccess={close} 
          initialData={editingService}
        />
      </FormDrawer>

      <FormDrawer
        opened={canaryOpened}
        onClose={closeCanary}
        title="Canary Deployment Wizard"
        width="narrow"
      >
        {canaryService && (
          <CanaryWizard 
            service={canaryService} 
            onSuccess={closeCanary}
          />
        )}
      </FormDrawer>
    </Stack>
  )
}
