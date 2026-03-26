import { Fragment, useState } from 'react'
import { Card, Title, Text, Stack, Group, Button, Drawer, Table, ActionIcon, Badge, TextInput, Center, Box, Menu, Tooltip, Paper, SimpleGrid, Pagination } from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { IconPlus, IconServer, IconSearch, IconDotsVertical, IconEdit, IconTrash, IconExternalLink, IconActivity, IconChevronDown, IconChevronRight } from '@tabler/icons-react'
import { useServices, apiFetch, getApiErrorMessage } from '../hooks/useGateon'
import { usePermissions } from '../hooks/usePermissions'
import { ServiceForm } from '../components/ServiceForm'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { notifications } from '@mantine/notifications'

export default function ServicesPage() {
  const { canWrite } = usePermissions()
  const [opened, { open, close }] = useDisclosure(false)
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

  const { data, isLoading } = useServices({
    page: page - 1,
    page_size: pageSize,
    search: search,
  })
  const queryClient = useQueryClient()

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiFetch(`/v1/services/${encodeURIComponent(id)}`, { method: 'DELETE' })
      if (!res.ok) throw new Error(await res.text())
      return true
    },
    onSuccess: () => {
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

  const handleEdit = (service: any) => {
    setEditingService(service)
    open()
  }

  const handleCreate = () => {
    setEditingService(null)
    open()
  }

  const services = data?.services || []
  const totalCount = data?.total_count || 0

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="center">
        <div>
          <Title order={2} fw={800} style={{ letterSpacing: -1 }}>Services</Title>
          <Text c="dimmed" size="sm" fw={500}>
            Define HTTP & gRPC backend targets and load balancing policies.
          </Text>
        </div>
        {canWrite && (
          <Button leftSection={<IconPlus size={18} />} onClick={handleCreate} size="md" radius="md">Create Service</Button>
        )}
      </Group>

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
                {data?.services?.reduce((acc, s) => acc + s.weighted_targets.length, 0) || 0}
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
            w={300}
          />

          <Box style={{ overflowX: 'auto' }}>
            <Table verticalSpacing="md" highlightOnHover layout="fixed">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th w={40} />
                  <Table.Th>Service</Table.Th>
                  <Table.Th>Targets</Table.Th>
                  <Table.Th>Policy</Table.Th>
                  <Table.Th>Health</Table.Th>
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
                  const isExpanded = expandedIds.has(s.id)
                  const firstTarget = s.weighted_targets[0]?.url || ''
                  const hasMore = s.weighted_targets.length > 1
                  return (
                    <Fragment key={s.id}>
                      <Table.Tr>
                        <Table.Td>
                          {s.weighted_targets.length > 0 && (
                            <ActionIcon
                              variant="subtle"
                              size="sm"
                              onClick={() => toggleExpand(s.id)}
                              style={{ visibility: hasMore ? 'visible' : 'hidden' }}
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
                                +{s.weighted_targets.length - 1} more
                              </Badge>
                            )}
                          </Stack>
                        </Table.Td>
                        <Table.Td>
                          <Text size="xs" fw={600} tt="capitalize">
                            {s.load_balancer_policy.replace(/_/g, ' ')}
                          </Text>
                        </Table.Td>
                        <Table.Td>
                          <Text size="xs" c="dimmed">{s.health_check_path || '—'}</Text>
                        </Table.Td>
                        <Table.Td>
                          {canWrite && (
                            <Menu shadow="md" position="bottom-end" transitionProps={{ transition: 'pop-top-right' }}>
                              <Menu.Target>
                                <ActionIcon variant="subtle" color="gray"><IconDotsVertical size={16} /></ActionIcon>
                              </Menu.Target>
                              <Menu.Dropdown>
                                <Menu.Label>Actions</Menu.Label>
                                <Menu.Item leftSection={<IconEdit size={14} />} onClick={() => handleEdit(s)}>Edit</Menu.Item>
                                <Menu.Divider />
                                <Menu.Item leftSection={<IconTrash size={14} />} color="red" onClick={() => deleteMutation.mutate(s.id)}>Delete</Menu.Item>
                              </Menu.Dropdown>
                            </Menu>
                          )}
                        </Table.Td>
                      </Table.Tr>
                      {isExpanded && hasMore && (
                        <Table.Tr>
                          <Table.Td colSpan={6} py="xs" style={{ backgroundColor: 'var(--mantine-color-dark-7)' }}>
                            <Stack gap={6} pl="md">
                              <Text size="xs" fw={600} c="dimmed">All targets</Text>
                              {s.weighted_targets.map((t, i) => (
                                <Group key={i} gap="sm">
                                  <Text size="xs" ff="monospace" c="dimmed">
                                    {t.url}
                                  </Text>
                                  <Badge variant="outline" size="xs">weight {t.weight}</Badge>
                                </Group>
                              ))}
                            </Stack>
                          </Table.Td>
                        </Table.Tr>
                      )}
                    </Fragment>
                  )
                })}
              </Table.Tbody>
            </Table>
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

      <Drawer
        opened={opened}
        onClose={close}
        title={<Text fw={800} size="xl" style={{ letterSpacing: -0.5 }}>{editingService ? 'Edit Service' : 'Create New Service'}</Text>}
        position="right"
        size="50%"
        padding="xl"
        styles={{
          header: { borderBottom: '1px solid var(--mantine-color-default-border)', marginBottom: 'xl' },
          content: { boxShadow: 'var(--mantine-shadow-xl)' }
        }}
      >
        <ServiceForm 
          onSuccess={close} 
          initialData={editingService}
        />
      </Drawer>
    </Stack>
  )
}
