// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import {
  Paper,
  TextInput,
  PasswordInput,
  Button,
  Title,
  Text,
  rem,
  Alert,
  Stack,
  Box,
  SimpleGrid,
  ThemeIcon,
  Group,
  ActionIcon,
  Tooltip,
  Badge,
  Stepper,
  Code,
  Select,
  Checkbox,
  Container,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { useNavigate } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import {
  IconLock,
  IconUser,
  IconAlertCircle,
  IconShieldCheck,
  IconRocket,
  IconServer,
  IconRefresh,
  IconCheck,
  IconInfoCircle,
  IconCopy,
} from "@tabler/icons-react";
import { setupGateon, testDbConnection } from "../hooks/useGateon";
import { notifications } from "@mantine/notifications";
import { useClipboard } from "@mantine/hooks";
import { useIsMobile } from "../hooks/useMobile";
import { generateRandomString } from "../utils/random";

const WIZARD_STEPS = 6; // Admin, Security, Database, Logging, Management, Review

type DbFields = {
  useUrl: boolean;
  url: string;
  driver: string;
  sqlitePath: string;
  host: string;
  port: string;
  user: string;
  password: string;
  name: string;
  sslMode: string;
};

// buildDbPayload validates a set of database fields and returns either a ready
// to send payload or a human-readable validation error.
function buildDbPayload(f: DbFields): { payload?: any; error?: string } {
  if (f.useUrl) {
    if (!f.url) return { error: "Please provide a database connection string (URL)" };
    return { payload: { databaseUrl: f.url } };
  }
  if (f.driver === "sqlite") {
    if (!f.sqlitePath) return { error: "Please provide a path for the SQLite database file" };
    return { payload: { databaseConfig: { driver: "sqlite", sqlitePath: f.sqlitePath } } };
  }
  if (!f.host || !f.port || !f.name) return { error: "Please fill host, port and database" };
  return {
    payload: {
      databaseConfig: {
        driver: f.driver,
        host: f.host,
        port: Number(f.port) || 0,
        user: f.user,
        password: f.password,
        database: f.name,
        sslMode: f.driver === "postgres" ? f.sslMode || "disable" : "",
      },
    },
  };
}

export default function SetupPage() {
  const [error, setError] = useState<string | null>(null);
  const isMobile = useIsMobile();
  const [loading, setLoading] = useState(false);
  const [wizardStep, setWizardStep] = useState(0);
  const clipboard = useClipboard({ timeout: 2000 });
  const navigate = useNavigate();

  const testDb = async (payload: any) => {
    setLoading(true);
    try {
      await testDbConnection(payload);
      return true;
    } catch (e: any) {
      setError(e?.message ? String(e.message) : "Database connection failed");
      return false;
    } finally {
      setLoading(false);
    }
  };

  const managementDbFields = (): DbFields => ({
    useUrl: form.values.databaseUseUrl,
    url: form.values.databaseUrl,
    driver: form.values.databaseDriver,
    sqlitePath: form.values.sqlitePath,
    host: form.values.dbHost,
    port: form.values.dbPort,
    user: form.values.dbUser,
    password: form.values.dbPassword,
    name: form.values.dbName,
    sslMode: form.values.dbSslMode,
  });

  const loggingDbFields = (): DbFields => ({
    useUrl: form.values.loggingUseUrl,
    url: form.values.loggingUrl,
    driver: form.values.loggingDriver,
    sqlitePath: form.values.loggingSqlitePath,
    host: form.values.logDbHost,
    port: form.values.logDbPort,
    user: form.values.logDbUser,
    password: form.values.logDbPassword,
    name: form.values.logDbName,
    sslMode: form.values.logDbSslMode,
  });

  const nextStep = async () => {
    const adminValid = form.validateField("adminUsername").hasError === false &&
      form.validateField("adminPassword").hasError === false &&
      form.validateField("confirmPassword").hasError === false;
    const securityValid = form.validateField("pasetoSecret").hasError === false;
    const managementValid = form.validateField("managementBind").hasError === false &&
      form.validateField("managementPort").hasError === false;

    if (wizardStep === 0 && !adminValid) {
      form.validate();
      return;
    }
    if (wizardStep === 1 && !securityValid) {
      form.validate();
      return;
    }
    if (wizardStep === 2) {
      // Database step: test connection before proceeding
      const { payload, error: dbError } = buildDbPayload(managementDbFields());
      if (dbError) {
        setError(dbError);
        return;
      }
      if (!(await testDb(payload))) return;
    }
    if (wizardStep === 3 && !form.values.loggingUseSame) {
      // Logging step: test the dedicated logging database connection
      const { payload, error: dbError } = buildDbPayload(loggingDbFields());
      if (dbError) {
        setError(dbError);
        return;
      }
      if (!(await testDb(payload))) return;
    }
    if (wizardStep === 4 && !managementValid) {
      form.validate();
      return;
    }
    setWizardStep((s) => Math.min(s + 1, WIZARD_STEPS - 1));
    setError(null);
  };

  const prevStep = () => {
    setWizardStep((s) => Math.max(s - 1, 0));
    setError(null);
  };

  const form = useForm({
    initialValues: {
      adminUsername: "admin",
      adminPassword: "",
      confirmPassword: "",
      pasetoSecret: "",
      managementBind: "0.0.0.0",
      managementPort: "8080",
      // Database fields
      databaseDriver: "sqlite",
      databaseUseUrl: false,
      databaseUrl: "",
      sqlitePath: "gateon.db",
      dbHost: "127.0.0.1",
      dbPort: "",
      dbUser: "",
      dbPassword: "",
      dbName: "gateon",
      dbSslMode: "disable",
      // Logging database fields (defaults to reusing the management database)
      loggingUseSame: true,
      loggingDriver: "sqlite",
      loggingUseUrl: false,
      loggingUrl: "",
      loggingSqlitePath: "gateon-logs.db",
      logDbHost: "127.0.0.1",
      logDbPort: "",
      logDbUser: "",
      logDbPassword: "",
      logDbName: "gateonLogs",
      logDbSslMode: "disable",
    },
    validate: {
      adminUsername: (value) => (value.length < 3 ? "Username too short" : null),
      adminPassword: (val) => (val.length < 8 ? "Password must be at least 8 characters" : null),
      confirmPassword: (val, values) => (val !== values.adminPassword ? "Passwords do not match" : null),
      pasetoSecret: (val) => (val.length !== 32 ? "Secret must be exactly 32 characters" : null),
      managementBind: (val) => (!val ? "Bind address is required" : null),
      managementPort: (val) => (!val ? "Port is required" : null),
    },
  });

  useEffect(() => {
    form.setFieldValue("pasetoSecret", generateRandomString(32));
  }, []);

  const handleSubmit = async (values: typeof form.values) => {
    setLoading(true);
    setError(null);
    try {
      const payload: any = {
        adminUsername: values.adminUsername,
        adminPassword: values.adminPassword,
        pasetoSecret: values.pasetoSecret,
        managementBind: values.managementBind,
        managementPort: values.managementPort,
      };
      if (values.databaseUseUrl) {
        payload.databaseUrl = values.databaseUrl;
      } else {
        if (values.databaseDriver === "sqlite") {
          payload.databaseConfig = {
            driver: "sqlite",
            sqlitePath: values.sqlitePath,
          };
        } else {
          payload.databaseConfig = {
            driver: values.databaseDriver,
            host: values.dbHost,
            port: Number(values.dbPort) || 0,
            user: values.dbUser,
            password: values.dbPassword,
            database: values.dbName,
            sslMode: values.databaseDriver === "postgres" ? values.dbSslMode || "disable" : "",
          };
        }
      }
      // Dedicated logging database (when the user opted out of reusing the management store)
      if (!values.loggingUseSame) {
        const { payload: logPayload } = buildDbPayload(loggingDbFields());
        if (logPayload?.databaseUrl) {
          payload.loggingDatabaseUrl = logPayload.databaseUrl;
        } else if (logPayload?.databaseConfig) {
          payload.loggingDatabaseConfig = logPayload.databaseConfig;
        }
      }
      const res = await setupGateon(payload);

      if (res.success) {
        notifications.show({
          title: "Setup Successful",
          message: "Gateon has been configured. Redirecting to login...",
          color: "green",
          icon: <IconCheck size={18} />,
        });
        setTimeout(() => navigate({ to: "/login" }), 1500);
      } else {
        setError(res.error || "Unknown error occurred during setup");
      }
    } catch (err: any) {
      setError(err.message || "Failed to connect to server");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box
      style={{
        minHeight: "100vh",
        overflowY: "auto",
        background: "var(--mantine-color-body)",
      }}
    >
      <Container size={760} py={48}>
        {/* Header / Branding */}
        <Stack align="center" gap="xs" mb="xl">
          <Group gap="sm">
            <ThemeIcon size={48} radius="md" variant="light" color="indigo">
              <IconRocket size={28} />
            </ThemeIcon>
            <Title order={1} fw={900} style={{ letterSpacing: -1 }}>
              GATEON
            </Title>
          </Group>
          <Badge size="lg" variant="light" color="indigo">
            First Run Experience
          </Badge>
          <Text c="dimmed" size="sm" ta="center" maw={520}>
            You're just a few steps away from a high-performance, secure
            networking environment. Configure your administrator access,
            security keys and data store below.
          </Text>
        </Stack>

        <Paper radius="lg" p={{ base: "lg", sm: "xl" }} withBorder shadow="sm">
          {error && (
            <Alert
              icon={<IconAlertCircle size="1.1rem" />}
              title="Setup Failed"
              color="red"
              variant="light"
              radius="md"
              mb="lg"
              withCloseButton
              onClose={() => setError(null)}
            >
              {error}
            </Alert>
          )}

          <form onSubmit={form.onSubmit(handleSubmit)} id="setup-form">
            <Stepper
              active={wizardStep}
              onStepClick={(s) => s < wizardStep && setWizardStep(s)}
              allowNextStepsSelect={false}
              size="xs"
              orientation={isMobile ? "vertical" : "horizontal"}
              iconSize={28}
              wrap={false}
              completedIcon={<IconCheck size={16} />}
              mb="xl"
              styles={{
                steps: { flexWrap: "nowrap", overflowX: isMobile ? undefined : "auto", paddingBottom: 4 },
                step: {
                  flexDirection: isMobile ? "row" : "column",
                  alignItems: "center",
                  gap: 6,
                  minWidth: 0,
                  flex: "1 1 auto",
                },
                stepBody: { marginInlineStart: isMobile ? 12 : 0, textAlign: isMobile ? "left" : "center" },
                separator: { minWidth: isMobile ? undefined : 8, marginInline: isMobile ? undefined : 4 },
                stepLabel: { fontSize: rem(11), lineHeight: 1.1 },
              }}
            >
              <Stepper.Step label="Account">
                <Stack gap="lg" mt="md">
                  <Box>
                    <Text size="xs" fw={700} c="dimmed" mb={10} style={{ textTransform: 'uppercase', letterSpacing: 1 }}>
                      Administrator Account
                    </Text>
                    <Stack gap="md">
                      <TextInput
                        label="Username"
                        placeholder="admin"
                        required
                        size="md"
                        leftSection={<IconUser size={rem(18)} stroke={1.5} />}
                        {...form.getInputProps("adminUsername")}
                      />
                      <SimpleGrid cols={{ base: 1, sm: 2 }}>
                        <PasswordInput
                          label="Password"
                          placeholder="••••••••"
                          required
                          size="md"
                          leftSection={<IconLock size={rem(18)} stroke={1.5} />}
                          rightSectionWidth={68}
                          {...form.getInputProps("adminPassword")}
                          rightSection={
                            <Group gap={0}>
                              <Tooltip label={clipboard.copied ? "Copied" : "Copy Password"}>
                                <ActionIcon
                                  onClick={() => clipboard.copy(form.values.adminPassword)}
                                  variant="subtle"
                                  color={clipboard.copied ? "teal" : "gray"}
                                >
                                  {clipboard.copied ? <IconCheck size="1.1rem" /> : <IconCopy size="1.1rem" />}
                                </ActionIcon>
                              </Tooltip>
                              <Tooltip label="Generate Password">
                                <ActionIcon
                                  onClick={() => {
                                    const pwd = generateRandomString(16);
                                    form.setFieldValue("adminPassword", pwd);
                                    form.setFieldValue("confirmPassword", pwd);
                                  }}
                                  variant="subtle"
                                >
                                  <IconRefresh size="1.1rem" />
                                </ActionIcon>
                              </Tooltip>
                            </Group>
                          }
                        />
                        <PasswordInput
                          label="Confirm"
                          placeholder="••••••••"
                          required
                          size="md"
                          leftSection={<IconShieldCheck size={rem(18)} stroke={1.5} />}
                          {...form.getInputProps("confirmPassword")}
                        />
                      </SimpleGrid>
                    </Stack>
                  </Box>
                </Stack>
              </Stepper.Step>

              <Stepper.Step label="Security">
                <Stack gap="lg" mt="md">
                  <Box>
                    <Group justify="space-between" mb={10}>
                      <Text size="xs" fw={700} c="dimmed" style={{ textTransform: 'uppercase', letterSpacing: 1 }}>
                        Security Configuration
                      </Text>
                      <Tooltip label="Required for PASETO token encryption">
                        <IconInfoCircle size={14} color="gray" />
                      </Tooltip>
                    </Group>
                    <TextInput
                      label="PASETO Secret Key"
                      placeholder="Exactly 32 characters"
                      required
                      size="md"
                      ff="monospace"
                      rightSectionWidth={68}
                      {...form.getInputProps("pasetoSecret")}
                      rightSection={
                        <Group gap={0}>
                          <Tooltip label={clipboard.copied ? "Copied" : "Copy Secret"}>
                            <ActionIcon
                              onClick={() => clipboard.copy(form.values.pasetoSecret)}
                              variant="subtle"
                              color={clipboard.copied ? "teal" : "gray"}
                            >
                              {clipboard.copied ? <IconCheck size="1.1rem" /> : <IconCopy size="1.1rem" />}
                            </ActionIcon>
                          </Tooltip>
                          <Tooltip label="Regenerate">
                            <ActionIcon
                              onClick={() => form.setFieldValue("pasetoSecret", generateRandomString(32))}
                              variant="subtle"
                            >
                              <IconRefresh size="1.1rem" />
                            </ActionIcon>
                          </Tooltip>
                        </Group>
                      }
                    />
                    <Text size="xs" c="dimmed" mt={5}>
                      This secret is used to encrypt your session tokens. Keep it safe.
                    </Text>
                  </Box>
                </Stack>
              </Stepper.Step>

              <Stepper.Step label="Database">
                <Stack gap="lg" mt="md">
                  <Box>
                    <Text size="xs" fw={700} c="dimmed" mb={10} style={{ textTransform: 'uppercase', letterSpacing: 1 }}>
                      Database Selection
                    </Text>
                    <SimpleGrid cols={{ base: 1, sm: 2 }}>
                      <Select
                        label="Driver"
                        data={[
                          { value: "sqlite", label: "SQLite" },
                          { value: "postgres", label: "PostgreSQL" },
                          { value: "mysql", label: "MySQL" },
                          { value: "mariadb", label: "MariaDB" },
                        ]}
                        {...form.getInputProps("databaseDriver")}
                      />
                      <Checkbox
                        mt={28}
                        label="Use connection string (URL)"
                        {...form.getInputProps("databaseUseUrl", { type: 'checkbox' })}
                      />
                    </SimpleGrid>

                    {form.values.databaseUseUrl ? (
                      <TextInput
                        mt="md"
                        label="Connection string"
                        placeholder="e.g. postgres://user:pass@host:5432/db?sslmode=disable"
                        {...form.getInputProps("databaseUrl")}
                      />
                    ) : form.values.databaseDriver === 'sqlite' ? (
                      <TextInput
                        mt="md"
                        label="SQLite file path"
                        placeholder="gateon.db"
                        {...form.getInputProps("sqlitePath")}
                      />
                    ) : (
                      <SimpleGrid cols={{ base: 1, sm: 2 }} mt="md">
                        <TextInput label="Host" placeholder="127.0.0.1" {...form.getInputProps("dbHost")} />
                        <TextInput label="Port" placeholder={form.values.databaseDriver === 'postgres' ? "5432" : "3306"} {...form.getInputProps("dbPort")} />
                        <TextInput label="User" placeholder="gateon" {...form.getInputProps("dbUser")} />
                        <PasswordInput label="Password" placeholder="••••••••" {...form.getInputProps("dbPassword")} />
                        <TextInput label="Database" placeholder="gateon" {...form.getInputProps("dbName")} />
                        {form.values.databaseDriver === 'postgres' && (
                          <Select
                            label="SSL mode"
                            data={[
                              { value: 'disable', label: 'disable' },
                              { value: 'require', label: 'require' },
                              { value: 'verify-ca', label: 'verify-ca' },
                              { value: 'verify-full', label: 'verify-full' },
                            ]}
                            {...form.getInputProps("dbSslMode")}
                          />
                        )}
                      </SimpleGrid>
                    )}

                    <Group mt="md">
                      <Button
                        variant="light"
                        loading={loading}
                        onClick={async () => {
                          try {
                            const useUrl = form.values.databaseUseUrl;
                            const driver = form.values.databaseDriver;
                            const payload: any = {};
                            if (useUrl) {
                              payload.databaseUrl = form.values.databaseUrl;
                            } else if (driver === 'sqlite') {
                              payload.databaseConfig = { driver: 'sqlite', sqlitePath: form.values.sqlitePath };
                            } else {
                              payload.databaseConfig = {
                                driver,
                                host: form.values.dbHost,
                                port: Number(form.values.dbPort) || 0,
                                user: form.values.dbUser,
                                password: form.values.dbPassword,
                                database: form.values.dbName,
                                sslMode: driver === 'postgres' ? form.values.dbSslMode || 'disable' : '',
                              };
                            }
                            setLoading(true);
                            await testDbConnection(payload);
                            notifications.show({ title: 'Database OK', message: 'Connection successful', color: 'green', icon: <IconCheck size={18} /> });
                            setError(null);
                          } catch (e: any) {
                            setError(e?.message ? String(e.message) : 'Database connection failed');
                          } finally {
                            setLoading(false);
                          }
                        }}
                      >
                        Test Connection
                      </Button>
                    </Group>
                  </Box>
                </Stack>
              </Stepper.Step>

              <Stepper.Step label="Logging">
                <Stack gap="lg" mt="md">
                  <Box>
                    <Text size="xs" fw={700} c="dimmed" mb={10} style={{ textTransform: 'uppercase', letterSpacing: 1 }}>
                      Logging Database
                    </Text>
                    <Text size="xs" c="dimmed" mb="md">
                      Choose where audit and security logs are stored. By default they
                      are kept in the management database, but you can isolate them in a
                      dedicated database.
                    </Text>
                    <Checkbox
                      label="Use the same database as management"
                      {...form.getInputProps("loggingUseSame", { type: 'checkbox' })}
                    />

                    {!form.values.loggingUseSame && (
                      <Box mt="md">
                        <SimpleGrid cols={{ base: 1, sm: 2 }}>
                          <Select
                            label="Driver"
                            data={[
                              { value: "sqlite", label: "SQLite" },
                              { value: "postgres", label: "PostgreSQL" },
                              { value: "mysql", label: "MySQL" },
                              { value: "mariadb", label: "MariaDB" },
                            ]}
                            {...form.getInputProps("loggingDriver")}
                          />
                          <Checkbox
                            mt={28}
                            label="Use connection string (URL)"
                            {...form.getInputProps("loggingUseUrl", { type: 'checkbox' })}
                          />
                        </SimpleGrid>

                        {form.values.loggingUseUrl ? (
                          <TextInput
                            mt="md"
                            label="Connection string"
                            placeholder="e.g. postgres://user:pass@host:5432/db?sslmode=disable"
                            {...form.getInputProps("loggingUrl")}
                          />
                        ) : form.values.loggingDriver === 'sqlite' ? (
                          <TextInput
                            mt="md"
                            label="SQLite file path"
                            placeholder="gateon-logs.db"
                            {...form.getInputProps("loggingSqlitePath")}
                          />
                        ) : (
                          <SimpleGrid cols={{ base: 1, sm: 2 }} mt="md">
                            <TextInput label="Host" placeholder="127.0.0.1" {...form.getInputProps("logDbHost")} />
                            <TextInput label="Port" placeholder={form.values.loggingDriver === 'postgres' ? "5432" : "3306"} {...form.getInputProps("logDbPort")} />
                            <TextInput label="User" placeholder="gateon" {...form.getInputProps("logDbUser")} />
                            <PasswordInput label="Password" placeholder="••••••••" {...form.getInputProps("logDbPassword")} />
                            <TextInput label="Database" placeholder="gateonLogs" {...form.getInputProps("logDbName")} />
                            {form.values.loggingDriver === 'postgres' && (
                              <Select
                                label="SSL mode"
                                data={[
                                  { value: 'disable', label: 'disable' },
                                  { value: 'require', label: 'require' },
                                  { value: 'verify-ca', label: 'verify-ca' },
                                  { value: 'verify-full', label: 'verify-full' },
                                ]}
                                {...form.getInputProps("logDbSslMode")}
                              />
                            )}
                          </SimpleGrid>
                        )}

                        <Group mt="md">
                          <Button
                            variant="light"
                            loading={loading}
                            onClick={async () => {
                              const { payload, error: dbError } = buildDbPayload(loggingDbFields());
                              if (dbError) {
                                setError(dbError);
                                return;
                              }
                              if (await testDb(payload)) {
                                notifications.show({ title: 'Database OK', message: 'Connection successful', color: 'green', icon: <IconCheck size={18} /> });
                                setError(null);
                              }
                            }}
                          >
                            Test Connection
                          </Button>
                        </Group>
                      </Box>
                    )}
                  </Box>
                </Stack>
              </Stepper.Step>

              <Stepper.Step label="API">
                <Stack gap="lg" mt="md">
                  <Box>
                    <Text size="xs" fw={700} c="dimmed" mb={10} style={{ textTransform: 'uppercase', letterSpacing: 1 }}>
                      Management Entrypoint
                    </Text>
                    <Alert color="orange" icon={<IconAlertCircle size={rem(18)} />} mb="md">
                      <Text size="sm" fw={500}>
                        Be careful when changing these values.
                      </Text>
                      <Text size="xs" mt={4}>
                        If you set an IP that you cannot reach, you will be locked out of the dashboard.
                        Use <Code>0.0.0.0</Code> to allow access from any IP (recommended for initial remote setup).
                        <Text fw={700} span> Note: Changes take effect after system restart.</Text>
                      </Text>
                    </Alert>
                    <SimpleGrid cols={{ base: 1, sm: 2 }}>
                      <TextInput
                        label="Bind Address"
                        placeholder="0.0.0.0 or admin.example.com"
                        required
                        size="md"
                        leftSection={<IconServer size={rem(18)} stroke={1.5} />}
                        {...form.getInputProps("managementBind")}
                      />
                      <TextInput
                        label="Port"
                        placeholder="8080"
                        required
                        size="md"
                        {...form.getInputProps("managementPort")}
                      />
                    </SimpleGrid>
                  </Box>
                </Stack>
              </Stepper.Step>

              <Stepper.Step label="Confirm">
                <Stack gap="lg" mt="md">
                  <Text size="sm" c="dimmed">
                    Review your configuration. global.json will be created when you confirm.
                  </Text>
                  <Paper p="md" withBorder radius="md" bg="light-dark(var(--mantine-color-gray-0), var(--mantine-color-dark-6))">
                    <Stack gap="xs">
                      <Group gap="xs">
                        <Text size="xs" fw={600} c="dimmed">Username:</Text>
                        <Code>{form.values.adminUsername}</Code>
                      </Group>
                      <Group gap="xs">
                        <Text size="xs" fw={600} c="dimmed">PASETO Secret:</Text>
                        <Code>•••••••• ({form.values.pasetoSecret.length} chars)</Code>
                      </Group>
                      <Group gap="xs">
                        <Text size="xs" fw={600} c="dimmed">Database:</Text>
                        {form.values.databaseUseUrl ? (
                          <Code>{form.values.databaseUrl || '—'}</Code>
                        ) : form.values.databaseDriver === 'sqlite' ? (
                          <Code>sqlite:{form.values.sqlitePath}</Code>
                        ) : (
                          <Code>{`${form.values.databaseDriver}://${form.values.dbUser ? form.values.dbUser + '@' : ''}${form.values.dbHost}:${form.values.dbPort}/${form.values.dbName}`}</Code>
                        )}
                      </Group>
                      <Group gap="xs">
                        <Text size="xs" fw={600} c="dimmed">Logging DB:</Text>
                        {form.values.loggingUseSame ? (
                          <Code>same as management</Code>
                        ) : form.values.loggingUseUrl ? (
                          <Code>{form.values.loggingUrl || '—'}</Code>
                        ) : form.values.loggingDriver === 'sqlite' ? (
                          <Code>sqlite:{form.values.loggingSqlitePath}</Code>
                        ) : (
                          <Code>{`${form.values.loggingDriver}://${form.values.logDbUser ? form.values.logDbUser + '@' : ''}${form.values.logDbHost}:${form.values.logDbPort}/${form.values.logDbName}`}</Code>
                        )}
                      </Group>
                      <Group gap="xs">
                        <Text size="xs" fw={600} c="dimmed">Management API:</Text>
                        <Code>{form.values.managementBind}:{form.values.managementPort}</Code>
                      </Group>
                    </Stack>
                  </Paper>
                </Stack>
              </Stepper.Step>
            </Stepper>

            <Group justify="space-between" mt="xl">
              <Button
                variant="default"
                onClick={prevStep}
                disabled={wizardStep === 0}
                size="md"
                radius="md"
              >
                Back
              </Button>
              {wizardStep < WIZARD_STEPS - 1 ? (
                <Button
                  size="md"
                  radius="md"
                  loading={loading}
                  className="bg-indigo-600 hover:bg-indigo-700"
                  onClick={nextStep}
                >
                  Next
                </Button>
              ) : (
                <Button
                  type="submit"
                  loading={loading}
                  size="md"
                  radius="md"
                  className="bg-indigo-600 hover:bg-indigo-700 transition-colors"
                >
                  Complete System Setup
                </Button>
              )}
            </Group>
          </form>
        </Paper>

        <Text size="xs" c="dimmed" ta="center" mt="lg">
          Securely powered by Gateon Open Source.
        </Text>
      </Container>
    </Box>
  );
}
