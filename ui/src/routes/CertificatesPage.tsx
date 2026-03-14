import { useState, useEffect } from 'react'
import { Card, Title, Text, Stack, TextInput, Button, Group, Divider, Alert, Paper, ActionIcon, FileButton, Table, Tooltip, ScrollArea, Modal } from '@mantine/core'
import { IconShieldLock, IconUpload, IconInfoCircle, IconPlus, IconCertificate, IconKey, IconTrash, IconPencil } from '@tabler/icons-react'
import { useDisclosure } from '@mantine/hooks'
import type { GlobalConfig, Certificate } from '../types/gateon'
import { apiFetch } from '../hooks/useGateon'
import { usePermissions } from '../hooks/usePermissions'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080'

export default function CertificatesPage() {
  const { canUploadCerts } = usePermissions()
  const [config, setConfig] = useState<GlobalConfig>({
    tls: { enabled: false },
  })
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [savedOk, setSavedOk] = useState(false)
  const [uploading, setUploading] = useState<Record<string, boolean>>({})
  const [opened, { open, close }] = useDisclosure(false)
  const [editingCert, setEditingCert] = useState<Certificate | null>(null)

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

  const handleUpload = async (field: 'cert_file' | 'key_file', file: File | null) => {
    if (!file) return
    
    setUploading(prev => ({ ...prev, [field]: true }))
    
    const formData = new FormData()
    formData.append('file', file)
    
    try {
      const res = await apiFetch("/v1/certs/upload", {
        method: 'POST',
        body: formData,
      })
      
      if (!res.ok) throw new Error(await res.text())
      
      const data = await res.json()
      if (editingCert) {
        setEditingCert({ ...editingCert, [field]: data.path })
      }
    } catch (err: any) {
      setError(`Upload failed: ${err.message}`)
    } finally {
      setUploading(prev => ({ ...prev, [field]: false }))
    }
  }

  const handleSaveCert = () => {
    if (!editingCert) return
    
    let updatedCerts = [...(config.tls?.certificates || [])]
    const index = updatedCerts.findIndex(c => c.id === editingCert.id)
    
    if (index >= 0) {
      updatedCerts[index] = editingCert
    } else {
      updatedCerts.push(editingCert)
    }
    
    const updatedConfig = {
      ...config,
      tls: {
        ...(config.tls || { enabled: false }),
        certificates: updatedCerts
      }
    }
    
    setConfig(updatedConfig)
    saveGatewayConfig(updatedConfig)
    close()
  }

  const removeCertificate = (id: string) => {
    const updatedCerts = (config.tls?.certificates || []).filter(c => c.id !== id)
    const updatedConfig = {
      ...config,
      tls: {
        ...(config.tls || { enabled: false }),
        certificates: updatedCerts
      }
    }
    setConfig(updatedConfig)
    saveGatewayConfig(updatedConfig)
  }

  const startAdd = () => {
    setEditingCert({ id: crypto.randomUUID(), name: '', cert_file: '', key_file: '' })
    open()
  }

  const startEdit = (cert: Certificate) => {
    setEditingCert({ ...cert })
    open()
  }

  const certificates = config.tls?.certificates || []

  return (
    <Stack gap="xl">
      <Group justify="space-between">
        <div>
          <Title order={2} fw={800} style={{ letterSpacing: -1 }}>Certificates</Title>
          <Text c="dimmed" size="sm">Manage SSL/TLS certificates for your domains.</Text>
        </div>
        {canUploadCerts && (
          <Button leftSection={<IconPlus size={16} />} onClick={startAdd}>Add Certificate</Button>
        )}
      </Group>

      <Alert icon={<IconInfoCircle size={16} />} color="blue" variant="light" radius="md">
        Certificates managed here can be used across multiple routes or assigned to entrypoints.
      </Alert>

      <Card withBorder padding={0} radius="lg" shadow="xs">
        <ScrollArea>
          <Table verticalSpacing="md" horizontalSpacing="xl">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Name</Table.Th>
                <Table.Th>Certificate File</Table.Th>
                <Table.Th>Key File</Table.Th>
                <Table.Th style={{ width: 100 }}>Actions</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {certificates.length === 0 ? (
                <Table.Tr>
                  <Table.Td colSpan={4} style={{ textAlign: 'center' }}>
                    <Text c="dimmed" py="xl">No certificates configured</Text>
                  </Table.Td>
                </Table.Tr>
              ) : (
                certificates.map((cert) => (
                  <Table.Tr key={cert.id}>
                    <Table.Td>
                      <Group gap="sm">
                        <IconCertificate size={16} color="var(--mantine-color-blue-6)" />
                        <Text fw={600}>{cert.name}</Text>
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" ff="monospace" c="dimmed">{cert.cert_file}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" ff="monospace" c="dimmed">{cert.key_file}</Text>
                    </Table.Td>
                    <Table.Td>
                      {canUploadCerts && (
                        <Group gap="xs" justify="flex-end">
                          <Tooltip label="Edit">
                            <ActionIcon variant="subtle" color="blue" onClick={() => startEdit(cert)}>
                              <IconPencil size={16} />
                            </ActionIcon>
                          </Tooltip>
                          <Tooltip label="Remove">
                            <ActionIcon variant="subtle" color="red" onClick={() => removeCertificate(cert.id)}>
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
      </Card>

      <Modal opened={opened} onClose={close} title={editingCert?.name ? 'Edit Certificate' : 'Add Certificate'} radius="lg">
        <Stack gap="md">
          <TextInput 
            label="Friendly Name" 
            placeholder="Wildcard *.example.com" 
            value={editingCert?.name || ''} 
            onChange={(e) => editingCert && setEditingCert({ ...editingCert, name: e.currentTarget.value })}
            radius="md"
          />
          <TextInput 
            label="Certificate File (.crt, .pem)" 
            placeholder="certs/example.crt"
            value={editingCert?.cert_file || ''} 
            onChange={(e) => editingCert && setEditingCert({ ...editingCert, cert_file: e.currentTarget.value })} 
            radius="md" 
            leftSection={<IconCertificate size={16} />}
            rightSection={
              <FileButton onChange={(f) => handleUpload('cert_file', f)} accept=".pem,.crt,.cer">
                {(props) => (
                  <Tooltip label="Upload Certificate">
                    <ActionIcon {...props} variant="subtle" loading={uploading['cert_file']}>
                      <IconUpload size={16} />
                    </ActionIcon>
                  </Tooltip>
                )}
              </FileButton>
            }
          />
          <TextInput 
            label="Private Key File (.key, .pem)" 
            placeholder="certs/example.key"
            value={editingCert?.key_file || ''} 
            onChange={(e) => editingCert && setEditingCert({ ...editingCert, key_file: e.currentTarget.value })} 
            radius="md" 
            leftSection={<IconKey size={16} />}
            rightSection={
              <FileButton onChange={(f) => handleUpload('key_file', f)} accept=".pem,.key">
                {(props) => (
                  <Tooltip label="Upload Private Key">
                    <ActionIcon {...props} variant="subtle" loading={uploading['key_file']}>
                      <IconUpload size={16} />
                    </ActionIcon>
                  </Tooltip>
                )}
              </FileButton>
            }
          />
          <Button onClick={handleSaveCert} radius="md" mt="md">Save Certificate</Button>
        </Stack>
      </Modal>

      {error && <Text c="red" size="sm" fw={600}>{error}</Text>}
      {savedOk && <Text c="green" size="sm" fw={600}>Certificates updated successfully!</Text>}
    </Stack>
  )
}
