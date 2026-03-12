import {
  Paper,
  TextInput,
  PasswordInput,
  Button,
  Title,
  Text,
  Center,
  rem,
  Alert,
  Stack,
  Box,
  SimpleGrid,
  ThemeIcon,
  Group,
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
} from "@tabler/icons-react";
import { useAuthStore } from "../store/useAuthStore";

const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8080";

export default function LoginPage() {
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeFeature, setActiveFeature] = useState(0);
  const navigate = useNavigate();
  const setAuth = useAuthStore((state) => state.setAuth);

  const features = [
    {
      icon: <IconShieldCheck size={24} />,
      title: "Secure Gateway",
      description: "Enterprise-grade security with JWT and PASETO authentication.",
    },
    {
      icon: <IconRocket size={24} />,
      title: "High Performance",
      description: "Ultra-fast Go-based proxy with minimal overhead and latency.",
    },
    {
      icon: <IconServer size={24} />,
      title: "Modern Management",
      description: "Real-time dashboard for traffic monitoring and configuration.",
    },
  ];

  useEffect(() => {
    const interval = setInterval(() => {
      setActiveFeature((prev) => (prev + 1) % features.length);
    }, 4000);
    return () => clearInterval(interval);
  }, []);

  const form = useForm({
    initialValues: {
      username: "",
      password: "",
    },
    validate: {
      username: (value) => (value.length < 1 ? "Username is required" : null),
      password: (value) => (value.length < 1 ? "Password is required" : null),
    },
  });

  const handleSubmit = async (values: typeof form.values) => {
    setLoading(true);
    setError(null);

    try {
      const res = await fetch(`${API_BASE_URL}/v1/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(values),
      });

      if (res.ok) {
        const data = await res.json();
        setAuth(data.token, data.user);
        navigate({ to: "/" });
      } else if (res.status === 401) {
        setError("Invalid username or password");
      } else {
        const text = await res.text();
        setError(`Access denied: ${text || res.statusText}`);
      }
    } catch (err) {
      setError(
        "Failed to connect to Gateon API. Please check if the gateway is running.",
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box style={{ height: "100vh", overflow: "hidden" }}>
      <SimpleGrid cols={{ base: 1, md: 2 }} spacing={0} style={{ height: "100%" }}>
        {/* Left Side: Animation & Branding */}
        <Box
          className="bg-gradient-to-br from-indigo-900 via-blue-900 to-slate-900"
          visibleFrom="md"
          style={{ height: "100%", display: "flex", flexDirection: "column", justifyContent: "center", padding: "40px", color: "white", position: "relative", overflow: "hidden" }}
        >
          {/* Decorative elements */}
          <Box style={{ position: "absolute", top: "-10%", left: "-10%", width: "40%", height: "40%", background: "radial-gradient(circle, rgba(99,102,241,0.15) 0%, rgba(0,0,0,0) 70%)", borderRadius: "50%" }} />
          <Box style={{ position: "absolute", bottom: "-10%", right: "-10%", width: "60%", height: "60%", background: "radial-gradient(circle, rgba(59,130,246,0.1) 0%, rgba(0,0,0,0) 70%)", borderRadius: "50%" }} />

          <Stack gap="xl" style={{ position: "relative", zIndex: 1 }}>
            <Group>
              <Box className="animate-pulse">
                <IconActivity size={48} color="white" />
              </Box>
              <Title order={1} fw={900} style={{ fontSize: rem(48), letterSpacing: -2, color: "white" }}>
                GATEON
              </Title>
            </Group>

            <Box mt="xl">
              <Title order={2} fw={700} mb="xs">
                Cloud-Native API Gateway
              </Title>
              <Text size="lg" c="gray.3" maw={500}>
                A high-performance, modular reverse proxy and load balancer built for modern infrastructure.
              </Text>
            </Box>

            <Stack gap="md" mt="xl">
              {features.map((feature, index) => (
                <Box
                  key={index}
                  p="md"
                  style={{
                    borderRadius: "12px",
                    background: index === activeFeature ? "rgba(255, 255, 255, 0.1)" : "transparent",
                    transition: "all 0.4s ease",
                    transform: index === activeFeature ? "translateX(10px)" : "none",
                    opacity: index === activeFeature ? 1 : 0.6,
                    borderLeft: index === activeFeature ? "4px solid white" : "4px solid transparent",
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
              &copy; {new Date().getFullYear()} Gateon. Professional Grade Networking.
            </Text>
          </Box>
        </Box>

        {/* Right Side: Sign-in Form */}
        <Box
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "40px",
            background: "var(--mantine-color-body)",
          }}
        >
          <Box maw={400} w="100%">
            <Paper radius="md" p={0}>
              <Box mb={40}>
                <Title order={2} fw={800} style={{ letterSpacing: -1 }}>
                  Welcome back
                </Title>
                <Text c="dimmed" size="sm" mt={5}>
                  Enter your credentials to manage your gateway
                </Text>
              </Box>

              {error && (
                <Alert
                  icon={<IconAlertCircle size="1.1rem" />}
                  title="Authentication Failed"
                  color="red"
                  variant="filled"
                  radius="md"
                  mb="xl"
                >
                  {error}
                </Alert>
              )}

              <form onSubmit={form.onSubmit(handleSubmit)}>
                <Stack gap="md">
                  <TextInput
                    label="Username"
                    placeholder="admin"
                    required
                    size="md"
                    leftSection={<IconUser size={rem(18)} stroke={1.5} />}
                    {...form.getInputProps("username")}
                  />
                  <PasswordInput
                    label="Password"
                    placeholder="Your password"
                    required
                    size="md"
                    leftSection={<IconLock size={rem(18)} stroke={1.5} />}
                    {...form.getInputProps("password")}
                  />
                  <Button
                    fullWidth
                    mt="lg"
                    type="submit"
                    loading={loading}
                    size="md"
                    radius="md"
                    className="bg-indigo-600 hover:bg-indigo-700 transition-colors"
                  >
                    Sign in to Dashboard
                  </Button>
                </Stack>
              </form>

              <Box mt={30} p="md" style={{ borderRadius: "8px", background: "var(--mantine-color-gray-0)" }}>
                <Text size="xs" ta="center" c="dimmed">
                  Developer access: <code style={{ fontWeight: 700 }}>admin</code> / <code style={{ fontWeight: 700 }}>password</code>
                </Text>
              </Box>
            </Paper>
          </Box>
        </Box>
      </SimpleGrid>
    </Box>
  );
}

