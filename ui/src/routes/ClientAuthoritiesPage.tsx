import { useState, useEffect } from 'react'
import { Card, Title, Text, Stack, TextInput, Button, Group, Divider, Alert, Paper, ActionIcon, FileButton, Table, Tooltip, ScrollArea, Modal } from '@mantine/core'
import { IconShieldLock, IconUpload, IconInfoCircle, IconPlus, IconTrash, IconLockCheck } from '@tabler/icons-react'
import { useDisclosure } from '@mantine/hooks'
import type { GlobalConfig, ClientAuthority } from '../types/gateon'
import { apiFetch } from '../hooks/useGateon'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080'

export default function ClientAuthoritiesPage() {
  const [config, setConfig] = useState<GlobalConfig>({
    tls: { enabled: false },
  })
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [savedOk, setSavedOk] = useState(false)
  const [uploading, setUploading] = useState<Record<string, boolean>>({})
  const [opened, { open, close }] = useDisclosure(false)
  const [editingCA, setEditingCA] = useState<ClientAuthority | null>(null)

  useEffect(() => {
    fetchConfig()
  }, [])

  const fetchConfig = () => {
    const controller = new AbortController()
    apiFetch("/v1/global", { signal: controller.signal })
      .then(async (r) => {
        if (!r.ok) throw new Error(await r.text())
        return r.json()
      })
      .then((cfg: GlobalConfig) => setConfig(cfg || { tls: { enabled: false } } as GlobalConfig))
      .catch(() => {})
    return () => controller.abort()
  }

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
    } catch (e: any) {
      setError(e.message || 'Failed to save configuration')
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
        setEditingCA({ ...editingCA, ca_file: data.path })
      }
    } catch (err: any) {
      setError(`Upload failed: ${err.message}`)
    } finally {
      setUploading(prev => ({ ...prev, current: false }))
    }
  }

  const handleSaveCA = () => {
    if (!editingCA) return
    
    let updatedCAs = [...(config.tls?.client_authorities || [])]
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
        client_authorities: updatedCAs
      }
    }
    
    setConfig(updatedConfig)
    saveGatewayConfig(updatedConfig)
    close()
  }

  const removeCA = (id: string) => {
    const updatedCAs = (config.tls?.client_authorities || []).filter(c => c.id !== id)
    const updatedConfig = {
      ...config,
      tls: {
        ...(config.tls || { enabled: false }),
        client_authorities: updatedCAs
      }
    }
    setConfig(updatedConfig)
    saveGatewayConfig(updatedConfig)
  }

  const startAdd = () => {
    setEditingCA({ id: crypto.randomUUID(), name: '', ca_file: '' })
    open()
  }

  const startEdit = (ca: ClientAuthority) => {
    setEditingCA({ ...ca })
    open()
  }

  const cas = config.tls?.client_authorities || []

  return (
    <Stack gap="xl">
      <Group justify="space-between">
        <div>
          <Title order={2} fw={800} style={{ letterSpacing: -1 }}>Client Authorities</Title>
          <Text c="dimmed" size="sm">Manage trusted Root CAs for mTLS client authentication.</Text>
        </div>
        <Button leftSection={<IconPlus size={16} />} onClick={startAdd}>Add CA</Button>
      </Group>

      <Alert icon={<IconInfoCircle size={16} />} color="blue" variant="light" radius="md">
        These CA certificates are used when the gateway or a specific route requires client certificate authentication.
      </Alert>

      <Card withBorder padding={0} radius="lg" shadow="xs">
        <ScrollArea>
          <Table verticalSpacing="md" horizontalSpacing="xl">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Name</Table.Th>
                <Table.Th>CA File Path</Table.Th>
                <Table.Th style={{ width: 100 }}>Actions</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {cas.length === 0 ? (
                <Table.Tr>
                  <Table.Td colSpan={3} style={{ textAlign: 'center' }}>
                    <Text c="dimmed" py="xl">No client authorities configured</Text>
                  </Table.Td>
                </Table.Tr>
              ) : (
                cas.map((ca) => (
                  <Table.Tr key={ca.id}>
                    <Table.Td>
                      <Group gap="sm">
                        <IconShieldLock size={16} color="var(--mantine-color-blue-6)" />
                        <Text fw={600}>{ca.name}</Text>
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" ff="monospace" c="dimmed">{ca.ca_file}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Group gap="xs" justify="flex-end">
                        <Tooltip label="Edit">
                          <ActionIcon variant="subtle" color="blue" onClick={() => startEdit(ca)}>
                            <IconLockCheck size={16} />
                          </ActionIcon>
                        </Tooltip>
                        <Tooltip label="Remove">
                          <ActionIcon variant="subtle" color="red" onClick={() => removeCA(ca.id)}>
                            <IconTrash size={16} />
                          </ActionIcon>
                        </Tooltip>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))
              )}
            </Table.Tbody>
          </Table>
        </ScrollArea>
      </Card>

      <Modal opened={opened} onClose={close} title={editingCA?.name ? 'Edit CA' : 'Add Client Authority'} radius="lg">
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
            value={editingCA?.ca_file || ''} 
            onChange={(e) => editingCA && setEditingCA({ ...editingCA, ca_file: e.currentTarget.value })} 
            radius="md" 
            leftSection={<IconLockCheck size={16} />}
            rightSection={
              <FileButton onChange={handleUpload} accept=".pem,.crt,.ca">
                {(props) => (
                  <Tooltip label="Upload CA Certificate">
                    <ActionIcon {...props} variant="subtle" loading={uploading['current']}>
                      <IconUpload size={16} />
                    </ActionIcon>
                  </Tooltip>
                )}
              </FileButton>
            }
          />
          <Button onClick={handleSaveCA} radius="md" mt="md">Save Authority</Button>
        </Stack>
      </Modal>

      {error && <Text c="red" size="sm" fw={600}>{error}</Text>}
      {savedOk && <Text c="green" size="sm" fw={600}>Client authorities updated successfully!</Text>}
    </Stack>
  )
}
