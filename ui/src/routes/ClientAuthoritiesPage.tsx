// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useState, useEffect, useMemo } from 'react'
import { Card, Title, Text, Stack, TextInput, Button, Group, Divider, Alert, Paper, ActionIcon, FileButton, Table, Tooltip, ScrollArea, Modal, Pagination, Box, Center, Select, Textarea } from '@mantine/core'
import { IconShieldLock, IconUpload, IconInfoCircle, IconPlus, IconTrash, IconLockCheck, IconClipboard, IconAlertTriangle } from '@tabler/icons-react'
import { useDisclosure } from '@mantine/hooks'
import type { GlobalConfig, ClientAuthority } from '../types/gateon'
import { apiFetch, getApiErrorMessage } from '../hooks/useGateon'
import { usePermissions } from '../hooks/usePermissions'
import { useGlobalConfigDraft } from '../hooks/useGlobalConfigDraft'
import { ConfirmDeleteModal } from '../components/ConfirmDelete'

export default function ClientAuthoritiesPage() {
  const { canUploadCerts } = usePermissions()
  // Nothing may be saved until the gateway's config has been read: see
  // useGlobalConfigDraft for what saving the placeholder did.
  const { config, setConfig, status, loadError, retry } = useGlobalConfigDraft()
  const canEdit = canUploadCerts && status === 'loaded'
  const [pendingDelete, setPendingDelete] = useState<ClientAuthority | null>(null)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [savedOk, setSavedOk] = useState(false)
  const [uploading, setUploading] = useState<Record<string, boolean>>({})
  const [opened, { open, close }] = useDisclosure(false)
  const [pasteOpened, { open: openPaste, close: closePaste }] = useDisclosure(false)
  const [editingCA, setEditingCA] = useState<ClientAuthority | null>(null)
  const [pasteContent, setPasteContent] = useState('')

  const saveGatewayConfig = async (newConfig: GlobalConfig) => {
    setSaving(true)
    setError(null)
    setSavedOk(false)
    try {
      const res = await apiFetch("/v1/global", {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newConfig),
      })
      if (!res.ok) throw new Error(await res.text())
      setSavedOk(true)
      setTimeout(() => setSavedOk(false), 3000)
    } catch (e: unknown) {
      setError(getApiErrorMessage(e) || 'Failed to save configuration')
    } finally {
      setSaving(false)
    }
  }

  const handleUpload = async (file: File | null) => {
    if (!file) return
    
    setUploading(prev => ({ ...prev, current: true }))
    
    const formData = new FormData()
    formData.append('file', file)
    
    try {
      const res = await apiFetch("/v1/certs/upload", {
        method: 'POST',
        body: formData,
      })
      
      if (!res.ok) throw new Error(await res.text())
      
      const data = await res.json()
      if (editingCA) {
        setEditingCA({ ...editingCA, caFile: data.path })
      }
    } catch (err: any) {
      setError(`Upload failed: ${err.message}`)
    } finally {
      setUploading(prev => ({ ...prev, current: false }))
    }
  }

  const handlePaste = async () => {
    if (!pasteContent) return
    
    setUploading(prev => ({ ...prev, current: true }))
    
    try {
      const res = await apiFetch("/v1/certs/paste", {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          content: pasteContent, 
          type: 'ca' 
        }),
      })
      
      if (!res.ok) throw new Error(await res.text())
      
      const data = await res.json()
      if (editingCA) {
        setEditingCA({ ...editingCA, caFile: data.path })
      }
      closePaste()
      setPasteContent('')
    } catch (err: any) {
      setError(`Paste failed: ${err.message}`)
    } finally {
      setUploading(prev => ({ ...prev, current: false }))
    }
  }

  const handleSaveCA = () => {
    if (!editingCA) return
    
    let updatedCAs = [...(config.tls?.clientAuthorities || [])]
    const index = updatedCAs.findIndex(c => c.id === editingCA.id)
    
    if (index >= 0) {
      updatedCAs[index] = editingCA
    } else {
      updatedCAs.push(editingCA)
    }
    
    const updatedConfig = {
      ...config,
      tls: {
        ...(config.tls || { enabled: false }),
        clientAuthorities: updatedCAs
      }
    }
    
    setConfig(updatedConfig)
    saveGatewayConfig(updatedConfig)
    close()
  }

  const removeCA = (id: string) => {
    const updatedCAs = (config.tls?.clientAuthorities || []).filter(c => c.id !== id)
    const updatedConfig = {
      ...config,
      tls: {
        ...(config.tls || { enabled: false }),
        clientAuthorities: updatedCAs
      }
    }
    setConfig(updatedConfig)
    saveGatewayConfig(updatedConfig)
  }

  const startAdd = () => {
    setEditingCA({ id: crypto.randomUUID(), name: '', caFile: '', clientAuthType: 'NoClientCert' })
    open()
  }

  const startEdit = (ca: ClientAuthority) => {
    setEditingCA({ ...ca })
    open()
  }

  const cas = config.tls?.clientAuthorities || []
  const emptyText =
    status === 'loaded' ? 'No client authorities configured' : status === 'loading' ? 'Loading client authorities…' : 'Unavailable until the authorities load.'
  const PAGE_SIZE = 10
  const [page, setPage] = useState(1)
  const paginatedCas = useMemo(() => {
    const start = (page - 1) * PAGE_SIZE
    return cas.slice(start, start + PAGE_SIZE)
  }, [cas, page])
  const totalPages = Math.max(1, Math.ceil(cas.length / PAGE_SIZE))
  useEffect(() => {
    if (page > totalPages && totalPages > 0) setPage(totalPages)
  }, [cas.length, totalPages, page])

  return (
    <Stack gap="xl">
      <Group justify="space-between">
        <div>
          <Title order={2} fw={800} style={{ letterSpacing: -1 }}>Client Authorities</Title>
          <Text c="dimmed" size="sm">Manage trusted Root CAs for mTLS client authentication.</Text>
        </div>
        {canUploadCerts && (
          <Button leftSection={<IconPlus size={16} />} onClick={startAdd} disabled={!canEdit}>Add CA</Button>
        )}
      </Group>

      {status === 'failed' && (
        <Alert color="red" variant="light" radius="md" icon={<IconAlertTriangle size={16} />} title="Client authorities could not be loaded">
          <Stack gap="xs">
            <Text size="sm">
              {loadError || 'The gateway did not answer.'} Adding and removing authorities is disabled until they
              load, so an empty list cannot be saved over the gateway's TLS settings.
            </Text>
            <Group>
              <Button size="xs" variant="light" color="red" onClick={retry}>Retry</Button>
            </Group>
          </Stack>
        </Alert>
      )}

      <Alert icon={<IconInfoCircle size={16} />} color="blue" variant="light" radius="md">
        These CA certificates are used when the gateway or a specific route requires client certificate authentication.
      </Alert>

      <Card withBorder padding={0} radius="lg" shadow="xs">
        <ScrollArea>
          <Table verticalSpacing="md" horizontalSpacing="xl" highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Name</Table.Th>
                <Table.Th>CA File Path</Table.Th>
                <Table.Th>Client Auth Type</Table.Th>
                <Table.Th style={{ width: 100 }}>Actions</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {cas.length === 0 ? (
                <Table.Tr>
                  <Table.Td colSpan={4}>
                    <Center py="xl">
                      <Text c="dimmed">{emptyText}</Text>
                    </Center>
                  </Table.Td>
                </Table.Tr>
              ) : (
                paginatedCas.map((ca) => (
                  <Table.Tr key={ca.id}>
                    <Table.Td>
                      <Group gap="sm">
                        <IconShieldLock size={16} color="var(--mantine-color-blue-6)" />
                        <Text fw={600}>{ca.name}</Text>
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" ff="monospace" c="dimmed">{ca.caFile}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{ca.clientAuthType || 'NoClientCert'}</Text>
                    </Table.Td>
                    <Table.Td>
                      {canUploadCerts && (
                        <Group gap="xs" justify="flex-end">
                          <Tooltip label="Edit">
                            <ActionIcon variant="subtle" color="blue" onClick={() => startEdit(ca)} aria-label={`Edit client authority ${ca.name || ca.id}`}>
                              <IconLockCheck size={16} />
                            </ActionIcon>
                          </Tooltip>
                          <Tooltip label="Remove">
                            <ActionIcon variant="subtle" color="red" onClick={() => setPendingDelete(ca)} aria-label={`Remove client authority ${ca.name || ca.id}`}>
                              <IconTrash size={16} />
                            </ActionIcon>
                          </Tooltip>
                        </Group>
                      )}
                    </Table.Td>
                  </Table.Tr>
                ))
              )}
            </Table.Tbody>
          </Table>
        </ScrollArea>
        {cas.length > PAGE_SIZE && (
          <Box p="md" style={{ borderTop: '1px solid var(--mantine-color-default-border)' }}>
            <Group justify="space-between" align="center">
              <Text size="xs" c="dimmed">
                Showing {((page - 1) * PAGE_SIZE) + 1}–{Math.min(page * PAGE_SIZE, cas.length)} of {cas.length}
              </Text>
              <Pagination
                total={totalPages}
                value={page}
                onChange={setPage}
                size="sm"
                radius="md"
              />
            </Group>
          </Box>
        )}
      </Card>

      <Modal opened={opened} onClose={close} title={editingCA && cas.some((c) => c.id === editingCA.id) ? 'Edit CA' : 'Add Client Authority'} radius="lg">
        <Stack gap="md">
          <TextInput 
            label="Name" 
            placeholder="Internal Root CA" 
            value={editingCA?.name || ''} 
            onChange={(e) => editingCA && setEditingCA({ ...editingCA, name: e.currentTarget.value })}
            radius="md"
          />
          <TextInput 
            label="CA Certificate File" 
            placeholder="certs/ca.crt"
            value={editingCA?.caFile || ''} 
            onChange={(e) => editingCA && setEditingCA({ ...editingCA, caFile: e.currentTarget.value })} 
            radius="md" 
            leftSection={<IconLockCheck size={16} />}
            rightSection={
              <Group gap={4} mr={4}>
                <Tooltip label="Paste CA Certificate">
                  <ActionIcon variant="subtle" color="blue" onClick={openPaste} aria-label="Paste CA certificate">
                    <IconClipboard size={16} />
                  </ActionIcon>
                </Tooltip>
                <FileButton onChange={handleUpload} accept=".pem,.crt,.ca">
                  {(props) => (
                    <Tooltip label="Upload CA Certificate">
                      <ActionIcon {...props} variant="subtle" loading={uploading['current']} aria-label="Upload CA certificate">
                        <IconUpload size={16} />
                      </ActionIcon>
                    </Tooltip>
                  )}
                </FileButton>
              </Group>
            }
          />
          <Select
            label="Client Auth Type"
            placeholder="Select client auth requirement"
            data={[
              { value: 'NoClientCert', label: 'NoClientCert (default)' },
              { value: 'RequestClientCert', label: 'RequestClientCert' },
              { value: 'RequireAnyClientCert', label: 'RequireAnyClientCert' },
              { value: 'VerifyClientCertIfGiven', label: 'VerifyClientCertIfGiven' },
              { value: 'RequireAndVerifyClientCert', label: 'RequireAndVerifyClientCert (mTLS)' },
            ]}
            value={editingCA?.clientAuthType || 'NoClientCert'}
            onChange={(val) => editingCA && setEditingCA({ ...editingCA, clientAuthType: val || 'NoClientCert' })}
            radius="md"
            description="Per-CA preference; actual enforcement occurs via TLS Options or global TLS clientAuthType."
          />
          <Button onClick={handleSaveCA} radius="md" mt="md">Save Authority</Button>
        </Stack>
      </Modal>

      <Modal opened={pasteOpened} onClose={closePaste} title="Paste CA Certificate" radius="lg">
        <Stack gap="md">
          <Textarea
            label="PEM Content"
            placeholder="-----BEGIN CERTIFICATE-----"
            minRows={10}
            maxRows={20}
            value={pasteContent}
            onChange={(e) => setPasteContent(e.currentTarget.value)}
            ff="monospace"
            size="xs"
            radius="md"
          />
          <Button onClick={handlePaste} loading={uploading['current']} disabled={!pasteContent}>
            Confirm and Save
          </Button>
        </Stack>
      </Modal>

      <ConfirmDeleteModal
        target={pendingDelete ? { kind: 'client authority', name: pendingDelete.name || pendingDelete.id } : null}
        consequence="Client certificates it issued are no longer accepted wherever it was the trusted CA."
        loading={saving}
        onCancel={() => setPendingDelete(null)}
        onConfirm={() => {
          if (pendingDelete) removeCA(pendingDelete.id)
          setPendingDelete(null)
        }}
      />

      {error && <Text c="red" size="sm" fw={600}>{error}</Text>}
      {savedOk && <Text c="green" size="sm" fw={600}>Client authorities updated successfully!</Text>}
    </Stack>
  )
}
