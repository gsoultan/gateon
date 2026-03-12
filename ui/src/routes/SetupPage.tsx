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
import { setupGateon } from "../hooks/useGateon";
import { notifications } from "@mantine/notifications";
import { useClipboard } from "@mantine/hooks";

const generateRandomString = (length: number) => {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
};

export default function SetupPage() {
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeStep, setActiveStep] = useState(0);
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

  const form = useForm({
    initialValues: {
      admin_username: "admin",
      admin_password: "",
      confirm_password: "",
      paseto_secret: "",
    },
    validate: {
      admin_username: (value) => (value.length < 3 ? "Username too short" : null),
      admin_password: (val) => (val.length < 8 ? "Password must be at least 8 characters" : null),
      confirm_password: (val, values) => (val !== values.admin_password ? "Passwords do not match" : null),
      paseto_secret: (val) => (val.length < 32 ? "Secret should be at least 32 characters" : null),
    },
  });

  useEffect(() => {
    form.setFieldValue("paseto_secret", generateRandomString(32));
  }, []);

  const handleSubmit = async (values: typeof form.values) => {
    setLoading(true);
    setError(null);
    try {
      const res = await setupGateon({
        admin_username: values.admin_username,
        admin_password: values.admin_password,
        paseto_secret: values.paseto_secret,
      });

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

              <form onSubmit={form.onSubmit(handleSubmit)}>
                <Stack gap="lg">
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

                  <Divider variant="dashed" my="sm" />

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

                  <Button
                    fullWidth
                    mt="xl"
                    type="submit"
                    loading={loading}
                    size="md"
                    radius="md"
                    className="bg-indigo-600 hover:bg-indigo-700 transition-colors"
                  >
                    Complete System Setup
                  </Button>
                </Stack>
              </form>
            </Paper>
          </Box>
        </Box>
      </SimpleGrid>
    </Box>
  );
}
