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
  Divider,
  Badge,
  Stepper,
  Code,
  Select,
  Checkbox,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { useNavigate } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import {
  IconLock,
  IconUser,
  IconAlertCircle,
  IconActivity,
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

const WIZARD_STEPS = 5; // Admin, Security, Database, Management, Review

export default function SetupPage() {
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeStep, setActiveStep] = useState(0);
  const [wizardStep, setWizardStep] = useState(0);
  const clipboard = useClipboard({ timeout: 2000 });
  const navigate = useNavigate();

  const features = [
    {
      icon: <IconShieldCheck size={24} />,
      title: "Secure Initialization",
      description: "Setup your primary administrator account with enterprise-grade security.",
    },
    {
      icon: <IconLock size={24} />,
      title: "PASETO Ready",
      description: "Generate unique Platform-Agnostic Security Tokens secrets automatically.",
    },
    {
      icon: <IconServer size={24} />,
      title: "Database Bootstrap",
      description: "Automatically provision and configure your gateway instance.",
    },
  ];

  useEffect(() => {
    const interval = setInterval(() => {
      setActiveStep((prev) => (prev + 1) % features.length);
    }, 4000);
    return () => clearInterval(interval);
  }, []);

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
      try {
        const useUrl = form.values.database_use_url;
        const driver = form.values.database_driver;
        const payload: any = {};
        if (useUrl) {
          if (!form.values.database_url) {
            setError("Please provide a database connection string (URL)");
            return;
          }
          payload.database_url = form.values.database_url;
        } else {
          if (driver === "sqlite") {
            if (!form.values.sqlite_path) {
              setError("Please provide a path for the SQLite database file");
              return;
            }
            payload.database_config = {
              driver: "sqlite",
              sqlite_path: form.values.sqlite_path,
            };
          } else {
            if (!form.values.db_host || !form.values.db_port || !form.values.db_name) {
              setError("Please fill host, port and database");
              return;
            }
            payload.database_config = {
              driver,
              host: form.values.db_host,
              port: Number(form.values.db_port) || 0,
              user: form.values.db_user,
              password: form.values.db_password,
              database: form.values.db_name,
              ssl_mode: driver === "postgres" ? form.values.db_ssl_mode || "disable" : "",
            };
          }
        }
        setLoading(true);
        await testDbConnection(payload);
      } catch (e: any) {
        setLoading(false);
        setError(e?.message ? String(e.message) : "Database connection failed");
        return;
      }
      setLoading(false);
    }
    if (wizardStep === 3 && !managementValid) {
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
    },
    validate: {
      admin_username: (value) => (value.length < 3 ? "Username too short" : null),
      admin_password: (val) => (val.length < 8 ? "Password must be at least 8 characters" : null),
      confirm_password: (val, values) => (val !== values.admin_password ? "Passwords do not match" : null),
      paseto_secret: (val) => (val.length < 32 ? "Secret should be at least 32 characters" : null),
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
    <Box style={{ height: "100vh", overflow: "hidden" }}>
      <SimpleGrid cols={{ base: 1, md: 2 }} spacing={0} style={{ height: "100%" }}>
        {/* Left Side: Branding & Info */}
        <Box
          className="bg-gradient-to-br from-slate-900 via-indigo-900 to-blue-900"
          visibleFrom="md"
          style={{ 
            height: "100%", 
            display: "flex", 
            flexDirection: "column", 
            justifyContent: "center", 
            padding: "40px", 
            color: "white", 
            position: "relative", 
            overflow: "hidden" 
          }}
        >
          {/* Decorative elements */}
          <Box style={{ position: "absolute", top: "-10%", right: "-10%", width: "50%", height: "50%", background: "radial-gradient(circle, rgba(99,102,241,0.1) 0%, rgba(0,0,0,0) 70%)", borderRadius: "50%" }} />
          
          <Stack gap="xl" style={{ position: "relative", zIndex: 1 }}>
            <Group>
              <Box className="animate-pulse">
                <IconRocket size={48} color="white" />
              </Box>
              <Title order={1} fw={900} style={{ fontSize: rem(48), letterSpacing: -2, color: "white" }}>
                GATEON
              </Title>
            </Group>

            <Box mt="xl">
              <Badge size="lg" variant="filled" color="indigo.4" mb="md">First Run Experience</Badge>
              <Title order={2} fw={700} mb="xs">
                Welcome to your new Gateway
              </Title>
              <Text size="lg" c="gray.3" maw={500}>
                You're just a few steps away from a high-performance, secure networking environment.
              </Text>
            </Box>

            <Stack gap="md" mt="xl">
              {features.map((feature, index) => (
                <Box
                  key={index}
                  p="md"
                  style={{
                    borderRadius: "12px",
                    background: index === activeStep ? "rgba(255, 255, 255, 0.1)" : "transparent",
                    transition: "all 0.4s ease",
                    transform: index === activeStep ? "translateX(10px)" : "none",
                    opacity: index === activeStep ? 1 : 0.6,
                    borderLeft: index === activeStep ? "4px solid white" : "4px solid transparent",
                  }}
                >
                  <Group>
                    <ThemeIcon color="white" variant="light" size="lg">
                      {feature.icon}
                    </ThemeIcon>
                    <Box>
                      <Text fw={700} color="white">{feature.title}</Text>
                      <Text size="sm" color="gray.4">{feature.description}</Text>
                    </Box>
                  </Group>
                </Box>
              ))}
            </Stack>
          </Stack>

          <Box mt="auto" pt="xl">
            <Text size="xs" color="gray.5">
              Securely powered by Gateon Open Source.
            </Text>
          </Box>
        </Box>

        {/* Right Side: Setup Form */}
        <Box
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "40px",
            background: "var(--mantine-color-body)",
            overflowY: "auto"
          }}
        >
          <Box maw={450} w="100%" py={40}>
            <Paper radius="md" p={0}>
              <Box mb={40}>
                <Title order={2} fw={800} style={{ letterSpacing: -1 }}>
                  Initialize System
                </Title>
                <Text c="dimmed" size="sm" mt={5}>
                  Configure your primary administrative access and security keys.
                </Text>
              </Box>

              {error && (
                <Alert
                  icon={<IconAlertCircle size="1.1rem" />}
                  title="Setup Failed"
                  color="red"
                  variant="filled"
                  radius="md"
                  mb="xl"
                >
                  {error}
                </Alert>
              )}

              <form
                onSubmit={form.onSubmit(handleSubmit)}
                id="setup-form"
              >
                <Stepper
                  active={wizardStep}
                  onStepClick={(s) => s < wizardStep && setWizardStep(s)}
                  allowNextStepsSelect={false}
                  size="sm"
                  mb="xl"
                >
                  <Stepper.Step label="Account" description="Admin user">
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

                  <Stepper.Step label="Security" description="PASETO key">
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
                      placeholder="32 character secret"
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

                  <Stepper.Step label="Database" description="Management store">
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
                          <>
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
                          </>
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

                  <Stepper.Step label="Management" description="API Access">
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

                  <Stepper.Step label="Confirm" description="Review & complete">
                    <Stack gap="lg" mt="md">
                      <Text size="sm" c="dimmed">
                        Review your configuration. global.json will be created when you confirm.
                      </Text>
                      <Paper p="md" withBorder radius="md" bg="gray.0">
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
          </Box>
        </Box>
      </SimpleGrid>
    </Box>
  );
}
