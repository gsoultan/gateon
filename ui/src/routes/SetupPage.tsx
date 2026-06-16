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
    return { payload: { database_url: f.url } };
  }
  if (f.driver === "sqlite") {
    if (!f.sqlitePath) return { error: "Please provide a path for the SQLite database file" };
    return { payload: { database_config: { driver: "sqlite", sqlite_path: f.sqlitePath } } };
  }
  if (!f.host || !f.port || !f.name) return { error: "Please fill host, port and database" };
  return {
    payload: {
      database_config: {
        driver: f.driver,
        host: f.host,
        port: Number(f.port) || 0,
        user: f.user,
        password: f.password,
        database: f.name,
        ssl_mode: f.driver === "postgres" ? f.sslMode || "disable" : "",
      },
    },
  };
}

export default function SetupPage() {
  const [error, setError] = useState<string | null>(null);
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
    useUrl: form.values.database_use_url,
    url: form.values.database_url,
    driver: form.values.database_driver,
    sqlitePath: form.values.sqlite_path,
    host: form.values.db_host,
    port: form.values.db_port,
    user: form.values.db_user,
    password: form.values.db_password,
    name: form.values.db_name,
    sslMode: form.values.db_ssl_mode,
  });

  const loggingDbFields = (): DbFields => ({
    useUrl: form.values.logging_use_url,
    url: form.values.logging_url,
    driver: form.values.logging_driver,
    sqlitePath: form.values.logging_sqlite_path,
    host: form.values.log_db_host,
    port: form.values.log_db_port,
    user: form.values.log_db_user,
    password: form.values.log_db_password,
    name: form.values.log_db_name,
    sslMode: form.values.log_db_ssl_mode,
  });

  const nextStep = async () => {
    const adminValid = form.validateField("admin_username").hasError === false &&
      form.validateField("admin_password").hasError === false &&
      form.validateField("confirm_password").hasError === false;
    const securityValid = form.validateField("paseto_secret").hasError === false;
    const managementValid = form.validateField("management_bind").hasError === false &&
      form.validateField("management_port").hasError === false;

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
    if (wizardStep === 3 && !form.values.logging_use_same) {
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
      admin_username: "admin",
      admin_password: "",
      confirm_password: "",
      paseto_secret: "",
      management_bind: "0.0.0.0",
      management_port: "8080",
      // Database fields
      database_driver: "sqlite",
      database_use_url: false,
      database_url: "",
      sqlite_path: "gateon.db",
      db_host: "127.0.0.1",
      db_port: "",
      db_user: "",
      db_password: "",
      db_name: "gateon",
      db_ssl_mode: "disable",
      // Logging database fields (defaults to reusing the management database)
      logging_use_same: true,
      logging_driver: "sqlite",
      logging_use_url: false,
      logging_url: "",
      logging_sqlite_path: "gateon-logs.db",
      log_db_host: "127.0.0.1",
      log_db_port: "",
      log_db_user: "",
      log_db_password: "",
      log_db_name: "gateon_logs",
      log_db_ssl_mode: "disable",
    },
    validate: {
      admin_username: (value) => (value.length < 3 ? "Username too short" : null),
      admin_password: (val) => (val.length < 8 ? "Password must be at least 8 characters" : null),
      confirm_password: (val, values) => (val !== values.admin_password ? "Passwords do not match" : null),
      paseto_secret: (val) => (val.length !== 32 ? "Secret must be exactly 32 characters" : null),
      management_bind: (val) => (!val ? "Bind address is required" : null),
      management_port: (val) => (!val ? "Port is required" : null),
    },
  });

  useEffect(() => {
    form.setFieldValue("paseto_secret", generateRandomString(32));
  }, []);

  const handleSubmit = async (values: typeof form.values) => {
    setLoading(true);
    setError(null);
    try {
      const payload: any = {
        admin_username: values.admin_username,
        admin_password: values.admin_password,
        paseto_secret: values.paseto_secret,
        management_bind: values.management_bind,
        management_port: values.management_port,
      };
      if (values.database_use_url) {
        payload.database_url = values.database_url;
      } else {
        if (values.database_driver === "sqlite") {
          payload.database_config = {
            driver: "sqlite",
            sqlite_path: values.sqlite_path,
          };
        } else {
          payload.database_config = {
            driver: values.database_driver,
            host: values.db_host,
            port: Number(values.db_port) || 0,
            user: values.db_user,
            password: values.db_password,
            database: values.db_name,
            ssl_mode: values.database_driver === "postgres" ? values.db_ssl_mode || "disable" : "",
          };
        }
      }
      // Dedicated logging database (when the user opted out of reusing the management store)
      if (!values.logging_use_same) {
        const { payload: logPayload } = buildDbPayload(loggingDbFields());
        if (logPayload?.database_url) {
          payload.logging_database_url = logPayload.database_url;
        } else if (logPayload?.database_config) {
          payload.logging_database_config = logPayload.database_config;
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
              iconSize={28}
              wrap={false}
              completedIcon={<IconCheck size={16} />}
              mb="xl"
              styles={{
                steps: { flexWrap: "nowrap", overflowX: "auto", paddingBottom: 4 },
                step: {
                  flexDirection: "column",
                  alignItems: "center",
                  gap: 6,
                  minWidth: 0,
                  flex: "1 1 auto",
                },
                stepBody: { marginInlineStart: 0, textAlign: "center" },
                separator: { minWidth: 8, marginInline: 4 },
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
                        {...form.getInputProps("admin_username")}
                      />
                      <SimpleGrid cols={{ base: 1, sm: 2 }}>
                        <PasswordInput
                          label="Password"
                          placeholder="••••••••"
                          required
                          size="md"
                          leftSection={<IconLock size={rem(18)} stroke={1.5} />}
                          rightSectionWidth={68}
                          {...form.getInputProps("admin_password")}
                          rightSection={
                            <Group gap={0}>
                              <Tooltip label={clipboard.copied ? "Copied" : "Copy Password"}>
                                <ActionIcon
                                  onClick={() => clipboard.copy(form.values.admin_password)}
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
                                    form.setFieldValue("admin_password", pwd);
                                    form.setFieldValue("confirm_password", pwd);
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
                          {...form.getInputProps("confirm_password")}
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
                      {...form.getInputProps("paseto_secret")}
                      rightSection={
                        <Group gap={0}>
                          <Tooltip label={clipboard.copied ? "Copied" : "Copy Secret"}>
                            <ActionIcon
                              onClick={() => clipboard.copy(form.values.paseto_secret)}
                              variant="subtle"
                              color={clipboard.copied ? "teal" : "gray"}
                            >
                              {clipboard.copied ? <IconCheck size="1.1rem" /> : <IconCopy size="1.1rem" />}
                            </ActionIcon>
                          </Tooltip>
                          <Tooltip label="Regenerate">
                            <ActionIcon
                              onClick={() => form.setFieldValue("paseto_secret", generateRandomString(32))}
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
                        {...form.getInputProps("database_driver")}
                      />
                      <Checkbox
                        mt={28}
                        label="Use connection string (URL)"
                        {...form.getInputProps("database_use_url", { type: 'checkbox' })}
                      />
                    </SimpleGrid>

                    {form.values.database_use_url ? (
                      <TextInput
                        mt="md"
                        label="Connection string"
                        placeholder="e.g. postgres://user:pass@host:5432/db?sslmode=disable"
                        {...form.getInputProps("database_url")}
                      />
                    ) : form.values.database_driver === 'sqlite' ? (
                      <TextInput
                        mt="md"
                        label="SQLite file path"
                        placeholder="gateon.db"
                        {...form.getInputProps("sqlite_path")}
                      />
                    ) : (
                      <SimpleGrid cols={{ base: 1, sm: 2 }} mt="md">
                        <TextInput label="Host" placeholder="127.0.0.1" {...form.getInputProps("db_host")} />
                        <TextInput label="Port" placeholder={form.values.database_driver === 'postgres' ? "5432" : "3306"} {...form.getInputProps("db_port")} />
                        <TextInput label="User" placeholder="gateon" {...form.getInputProps("db_user")} />
                        <PasswordInput label="Password" placeholder="••••••••" {...form.getInputProps("db_password")} />
                        <TextInput label="Database" placeholder="gateon" {...form.getInputProps("db_name")} />
                        {form.values.database_driver === 'postgres' && (
                          <Select
                            label="SSL mode"
                            data={[
                              { value: 'disable', label: 'disable' },
                              { value: 'require', label: 'require' },
                              { value: 'verify-ca', label: 'verify-ca' },
                              { value: 'verify-full', label: 'verify-full' },
                            ]}
                            {...form.getInputProps("db_ssl_mode")}
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
                            const useUrl = form.values.database_use_url;
                            const driver = form.values.database_driver;
                            const payload: any = {};
                            if (useUrl) {
                              payload.database_url = form.values.database_url;
                            } else if (driver === 'sqlite') {
                              payload.database_config = { driver: 'sqlite', sqlite_path: form.values.sqlite_path };
                            } else {
                              payload.database_config = {
                                driver,
                                host: form.values.db_host,
                                port: Number(form.values.db_port) || 0,
                                user: form.values.db_user,
                                password: form.values.db_password,
                                database: form.values.db_name,
                                ssl_mode: driver === 'postgres' ? form.values.db_ssl_mode || 'disable' : '',
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
                      {...form.getInputProps("logging_use_same", { type: 'checkbox' })}
                    />

                    {!form.values.logging_use_same && (
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
                            {...form.getInputProps("logging_driver")}
                          />
                          <Checkbox
                            mt={28}
                            label="Use connection string (URL)"
                            {...form.getInputProps("logging_use_url", { type: 'checkbox' })}
                          />
                        </SimpleGrid>

                        {form.values.logging_use_url ? (
                          <TextInput
                            mt="md"
                            label="Connection string"
                            placeholder="e.g. postgres://user:pass@host:5432/db?sslmode=disable"
                            {...form.getInputProps("logging_url")}
                          />
                        ) : form.values.logging_driver === 'sqlite' ? (
                          <TextInput
                            mt="md"
                            label="SQLite file path"
                            placeholder="gateon-logs.db"
                            {...form.getInputProps("logging_sqlite_path")}
                          />
                        ) : (
                          <SimpleGrid cols={{ base: 1, sm: 2 }} mt="md">
                            <TextInput label="Host" placeholder="127.0.0.1" {...form.getInputProps("log_db_host")} />
                            <TextInput label="Port" placeholder={form.values.logging_driver === 'postgres' ? "5432" : "3306"} {...form.getInputProps("log_db_port")} />
                            <TextInput label="User" placeholder="gateon" {...form.getInputProps("log_db_user")} />
                            <PasswordInput label="Password" placeholder="••••••••" {...form.getInputProps("log_db_password")} />
                            <TextInput label="Database" placeholder="gateon_logs" {...form.getInputProps("log_db_name")} />
                            {form.values.logging_driver === 'postgres' && (
                              <Select
                                label="SSL mode"
                                data={[
                                  { value: 'disable', label: 'disable' },
                                  { value: 'require', label: 'require' },
                                  { value: 'verify-ca', label: 'verify-ca' },
                                  { value: 'verify-full', label: 'verify-full' },
                                ]}
                                {...form.getInputProps("log_db_ssl_mode")}
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
                        {...form.getInputProps("management_bind")}
                      />
                      <TextInput
                        label="Port"
                        placeholder="8080"
                        required
                        size="md"
                        {...form.getInputProps("management_port")}
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
                        <Code>{form.values.admin_username}</Code>
                      </Group>
                      <Group gap="xs">
                        <Text size="xs" fw={600} c="dimmed">PASETO Secret:</Text>
                        <Code>•••••••• ({form.values.paseto_secret.length} chars)</Code>
                      </Group>
                      <Group gap="xs">
                        <Text size="xs" fw={600} c="dimmed">Database:</Text>
                        {form.values.database_use_url ? (
                          <Code>{form.values.database_url || '—'}</Code>
                        ) : form.values.database_driver === 'sqlite' ? (
                          <Code>sqlite:{form.values.sqlite_path}</Code>
                        ) : (
                          <Code>{`${form.values.database_driver}://${form.values.db_user ? form.values.db_user + '@' : ''}${form.values.db_host}:${form.values.db_port}/${form.values.db_name}`}</Code>
                        )}
                      </Group>
                      <Group gap="xs">
                        <Text size="xs" fw={600} c="dimmed">Logging DB:</Text>
                        {form.values.logging_use_same ? (
                          <Code>same as management</Code>
                        ) : form.values.logging_use_url ? (
                          <Code>{form.values.logging_url || '—'}</Code>
                        ) : form.values.logging_driver === 'sqlite' ? (
                          <Code>sqlite:{form.values.logging_sqlite_path}</Code>
                        ) : (
                          <Code>{`${form.values.logging_driver}://${form.values.log_db_user ? form.values.log_db_user + '@' : ''}${form.values.log_db_host}:${form.values.log_db_port}/${form.values.log_db_name}`}</Code>
                        )}
                      </Group>
                      <Group gap="xs">
                        <Text size="xs" fw={600} c="dimmed">Management API:</Text>
                        <Code>{form.values.management_bind}:{form.values.management_port}</Code>
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
