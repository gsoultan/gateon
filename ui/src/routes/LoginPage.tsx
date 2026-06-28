import {
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
  Image,
  Code,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { useNavigate } from "@tanstack/react-router";
import { useState, useEffect, useRef } from "react";
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
import { getApiBaseUrl } from "../store/useApiConfigStore";

export default function LoginPage() {
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeFeature, setActiveFeature] = useState(0);
  const [step, setStep] = useState<"login" | "2fa" | "2fa-setup">("login");
  const [tempUser, setTempUser] = useState<any>(null);
  const [enrollData, setEnrollData] = useState<{
    id: string;
    secret: string;
    qr_code_url: string;
    recovery_codes: string[];
  } | null>(null);
  const [tfaCode, setTfaCode] = useState("");
  const tfaInputRef = useRef<HTMLInputElement>(null);
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

  // Move focus to the verification code field when the 2FA step appears so
  // keyboard and screen-reader users land on the only relevant input. This is
  // an explicit, expected context change (preferred over the `autoFocus` prop).
  useEffect(() => {
    if (step === "2fa" || step === "2fa-setup") {
      tfaInputRef.current?.focus();
    }
  }, [step]);

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
      const res = await fetch(`${getApiBaseUrl()}/v1/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(values),
        credentials: "include", // allow session cookie to be set
      });

      if (res.ok) {
        const data = await res.json();
        if (data.two_factor_required) {
          setTempUser(data.user);
          setStep("2fa");
        } else if (data.two_factor_setup_required) {
          // Administrator mandated 2FA but the user hasn't enrolled. Begin
          // first-time enrollment (re-uses the just-entered password).
          await startEnrollment(values.username, values.password);
        } else {
          setAuth(data.token, data.user);
          navigate({ to: "/" });
        }
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

  const handle2FAVerify = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${getApiBaseUrl()}/v1/auth/2fa/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: tempUser.id, code: tfaCode }),
        credentials: "include",
      });

      if (res.ok) {
        const data = await res.json();
        if (data.success) {
          setAuth(data.token, data.user);
          navigate({ to: "/" });
        } else {
          setError("Invalid 2FA code");
        }
      } else {
        setError("Failed to verify 2FA code");
      }
    } catch (err) {
      setError("Connection error");
    } finally {
      setLoading(false);
    }
  };

  const startEnrollment = async (username: string, password: string) => {
    setError(null);
    try {
      const res = await fetch(`${getApiBaseUrl()}/v1/auth/2fa/enroll`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
        credentials: "include",
      });
      if (res.ok) {
        const data = await res.json();
        setEnrollData(data);
        setTempUser({ id: data.id });
        setTfaCode("");
        setStep("2fa-setup");
      } else {
        const text = await res.text();
        setError(`Could not start 2FA setup: ${text || res.statusText}`);
      }
    } catch (err) {
      setError("Connection error while starting 2FA setup");
    }
  };

  return (
    <Box style={{ height: "100vh", overflow: "hidden" }}>
      <SimpleGrid cols={{ base: 1, md: 2 }} spacing={0} style={{ height: "100%" }}>
        {/* Left Side: Branding & Features */}
        <Box
          className="bg-slate-950 relative overflow-hidden"
          visibleFrom="md"
          style={{ 
            height: "100%", 
            display: "flex", 
            flexDirection: "column", 
            justifyContent: "center", 
            padding: "60px",
            color: "white" 
          }}
        >
          {/* Animated Background Elements */}
          <Box 
            className="absolute -top-[10%] -left-[10%] w-[60%] h-[60%] rounded-full blur-[120px] opacity-20 bg-indigo-600 animate-pulse" 
            style={{ animationDuration: '10s' }}
          />
          <Box 
            className="absolute -bottom-[15%] -right-[10%] w-[70%] h-[70%] rounded-full blur-[140px] opacity-10 bg-blue-500 animate-pulse"
            style={{ animationDuration: '15s' }}
          />
          <Box 
            className="absolute top-1/4 left-1/2 w-[40%] h-[40%] rounded-full blur-[100px] opacity-10 bg-purple-600"
          />

          <Stack gap={40} style={{ position: "relative", zIndex: 1 }}>
            <Group align="center" gap="md">
              <Box className="bg-white/10 p-3 rounded-2xl backdrop-blur-md border border-white/20 shadow-xl">
                <IconActivity size={40} className="text-indigo-400" />
              </Box>
              <Box>
                <Title order={1} fw={900} style={{ fontSize: rem(42), letterSpacing: -1.5, lineHeight: 1 }}>
                  GATEON
                </Title>
                <Text size="xs" fw={700} className="tracking-[0.2em] text-indigo-400/80 uppercase">
                  Enterprise Proxy
                </Text>
              </Box>
            </Group>

            <Box>
              <Title order={2} fw={800} mb="md" style={{ fontSize: rem(36), lineHeight: 1.2 }}>
                The next generation of <br />
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-blue-400">
                  API management.
                </span>
              </Title>
              <Text size="lg" c="gray.4" maw={480} style={{ lineHeight: 1.6 }}>
                Secure, scale, and monitor your infrastructure with our lightning-fast, 
                cloud-native gateway. Designed for modern DevOps teams.
              </Text>
            </Box>

            <Stack gap="lg">
              {features.map((feature, index) => (
                <Box
                  key={index}
                  p="lg"
                  className="group"
                  style={{
                    borderRadius: "16px",
                    background: index === activeFeature ? "rgba(255, 255, 255, 0.05)" : "transparent",
                    border: index === activeFeature ? "1px solid rgba(255, 255, 255, 0.1)" : "1px solid transparent",
                    backdropFilter: index === activeFeature ? "blur(10px)" : "none",
                    transition: "all 0.5s cubic-bezier(0.4, 0, 0.2, 1)",
                    transform: index === activeFeature ? "translateX(12px)" : "none",
                    opacity: index === activeFeature ? 1 : 0.4,
                  }}
                >
                  <Group align="flex-start" wrap="nowrap">
                    <ThemeIcon 
                      variant="gradient" 
                      gradient={{ from: 'indigo', to: 'blue' }}
                      size={44}
                      radius="md"
                      className="shadow-lg shadow-indigo-500/20"
                    >
                      {feature.icon}
                    </ThemeIcon>
                    <Box>
                      <Text fw={700} size="lg" color="white" mb={4}>{feature.title}</Text>
                      <Text size="sm" color="gray.4" style={{ lineHeight: 1.5 }}>{feature.description}</Text>
                    </Box>
                  </Group>
                </Box>
              ))}
            </Stack>
          </Stack>

          <Box mt="auto" pt={40} style={{ position: "relative", zIndex: 1 }}>
            <Group justify="space-between" className="border-t border-white/10 pt-6">
              <Text size="xs" color="gray.5">
                &copy; {new Date().getFullYear()} Gateon Systems. All rights reserved.
              </Text>
              <Group gap="xs">
                <Text size="xs" className="text-gray-500 hover:text-gray-300 cursor-pointer transition-colors">Documentation</Text>
                <Box className="w-1 h-1 rounded-full bg-gray-700" />
                <Text size="xs" className="text-gray-500 hover:text-gray-300 cursor-pointer transition-colors">Support</Text>
              </Group>
            </Group>
          </Box>
        </Box>

        {/* Right Side: Sign-in Form */}
        <Box
          className="bg-white dark:bg-slate-950"
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "40px",
          }}
        >
          <Box maw={420} w="100%">
            <Box mb={50}>
              <Box hiddenFrom="md" mb={30}>
                 <Group gap="xs">
                    <IconActivity size={32} className="text-indigo-600" />
                    <Title order={3} fw={900} className="tracking-tight">GATEON</Title>
                 </Group>
              </Box>
              <Title order={2} fw={900} style={{ fontSize: rem(32), letterSpacing: -1 }}>
                {step === "login"
                  ? "Sign In"
                  : step === "2fa-setup"
                    ? "Set Up Two-Factor"
                    : "Verify Identity"}
              </Title>
              <Text c="dimmed" size="md" mt={8}>
                {step === "login"
                  ? "Welcome back! Please enter your details."
                  : step === "2fa-setup"
                    ? "Your administrator requires two-factor authentication. Enroll your device to continue."
                    : "Enter the code from your authenticator app."}
              </Text>
            </Box>

            {error && (
              <Alert
                icon={<IconAlertCircle size="1.1rem" />}
                color="red"
                variant="light"
                radius="lg"
                mb="xl"
                className="border border-red-100 dark:border-red-900/30"
              >
                {error}
              </Alert>
            )}

            {step === "login" ? (
              <form onSubmit={form.onSubmit(handleSubmit)}>
                <Stack gap="xl">
                  <TextInput
                    label="Username"
                    placeholder="Enter your username"
                    required
                    size="lg"
                    radius="lg"
                    leftSection={<IconUser size={20} stroke={1.5} className="text-gray-400" />}
                    {...form.getInputProps("username")}
                    styles={{
                      input: {
                        transition: 'border-color 0.2s ease, box-shadow 0.2s ease',
                        '&:focus': {
                          borderColor: 'var(--mantine-color-indigo-filled)',
                        }
                      },
                      label: {
                        marginBottom: 8,
                        fontWeight: 600
                      }
                    }}
                  />
                  <Box>
                    <Group justify="space-between" mb={8}>
                       <Text size="sm" fw={600} component="label">Password</Text>
                       <Text size="xs" fw={600} className="text-indigo-600 hover:text-indigo-700 cursor-pointer">
                         Forgot password?
                       </Text>
                    </Group>
                    <PasswordInput
                      placeholder="••••••••"
                      required
                      size="lg"
                      radius="lg"
                      leftSection={<IconLock size={20} stroke={1.5} className="text-gray-400" />}
                      {...form.getInputProps("password")}
                      styles={{
                        input: {
                          transition: 'border-color 0.2s ease, box-shadow 0.2s ease',
                          '&:focus': {
                            borderColor: 'var(--mantine-color-indigo-filled)',
                          }
                        }
                      }}
                    />
                  </Box>

                  <Button
                    fullWidth
                    type="submit"
                    loading={loading}
                    size="lg"
                    radius="lg"
                    className="bg-indigo-600 hover:bg-indigo-700 transition-all duration-200 shadow-lg shadow-indigo-600/20 active:scale-[0.98]"
                    style={{ height: rem(54) }}
                  >
                    Continue to Dashboard
                  </Button>
                </Stack>
              </form>
            ) : step === "2fa-setup" ? (
              <Stack gap="lg">
                {enrollData && (
                  <>
                    <Text size="sm" fw={600}>
                      1. Scan this QR code with your authenticator app
                    </Text>
                    <Group justify="center">
                      <Image
                        src={enrollData.qr_code_url}
                        w={180}
                        h={180}
                        alt="2FA QR code"
                      />
                    </Group>
                    <Text size="xs" c="dimmed" ta="center">
                      Or enter this secret manually: <Code>{enrollData.secret}</Code>
                    </Text>
                    {enrollData.recovery_codes?.length > 0 && (
                      <>
                        <Text size="sm" fw={600}>
                          2. Save your recovery codes
                        </Text>
                        <Alert color="blue" variant="light" radius="md">
                          <Text size="xs">
                            Store these somewhere safe. If you lose your device, they
                            are the only way back into your account.
                          </Text>
                        </Alert>
                        <SimpleGrid cols={2} spacing="xs">
                          {enrollData.recovery_codes.map((c) => (
                            <Code key={c} block>
                              {c}
                            </Code>
                          ))}
                        </SimpleGrid>
                      </>
                    )}
                    <Text size="sm" fw={600}>
                      3. Enter the 6-digit code to finish enrollment
                    </Text>
                  </>
                )}
                <TextInput
                  label="Verification Code"
                  placeholder="000 000"
                  required
                  size="lg"
                  radius="lg"
                  value={tfaCode}
                  onChange={(e) => setTfaCode(e.currentTarget.value)}
                  ref={tfaInputRef}
                  styles={{
                    input: {
                      textAlign: "center",
                      fontSize: rem(24),
                      letterSpacing: rem(8),
                      fontWeight: 700,
                    },
                    label: { marginBottom: 8, fontWeight: 600 },
                  }}
                />
                <Button
                  fullWidth
                  onClick={handle2FAVerify}
                  loading={loading}
                  size="lg"
                  radius="lg"
                  className="bg-indigo-600 hover:bg-indigo-700 shadow-lg shadow-indigo-600/20 active:scale-[0.98]"
                  style={{ height: rem(54) }}
                >
                  Verify & Enable
                </Button>
                <Button
                  variant="subtle"
                  color="gray"
                  fullWidth
                  onClick={() => {
                    setStep("login");
                    setEnrollData(null);
                    setTfaCode("");
                  }}
                  radius="lg"
                >
                  Back to login
                </Button>
              </Stack>
            ) : (
              <Stack gap="xl">
                <TextInput
                  label="Verification Code"
                  placeholder="000 000"
                  required
                  size="lg"
                  radius="lg"
                  value={tfaCode}
                  onChange={(e) => setTfaCode(e.currentTarget.value)}
                  ref={tfaInputRef}
                  className="text-center tracking-[0.5em] font-mono"
                  styles={{
                    input: {
                      textAlign: 'center',
                      fontSize: rem(24),
                      letterSpacing: rem(8),
                      fontWeight: 700
                    },
                    label: {
                      marginBottom: 8,
                      fontWeight: 600
                    }
                  }}
                />
                <Button
                  fullWidth
                  onClick={handle2FAVerify}
                  loading={loading}
                  size="lg"
                  radius="lg"
                  className="bg-indigo-600 hover:bg-indigo-700 shadow-lg shadow-indigo-600/20 active:scale-[0.98]"
                  style={{ height: rem(54) }}
                >
                  Verify & Sign in
                </Button>
                <Button variant="subtle" color="gray" fullWidth onClick={() => setStep("login")} radius="lg">
                  Back to login
                </Button>
              </Stack>
            )}

            <Box mt={60} className="text-center">
               <Text size="xs" color="dimmed">
                 Trusted by thousands of developers worldwide.
               </Text>
            </Box>
          </Box>
        </Box>
      </SimpleGrid>
    </Box>
  );
}

