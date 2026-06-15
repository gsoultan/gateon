import { Card, Title, Text, Stack, SegmentedControl, Group, Paper, Center, Select } from "@mantine/core";
import {
  IconPalette,
  IconSun,
  IconMoon,
  IconDeviceDesktop,
  IconBaselineDensityMedium,
  IconBaselineDensitySmall,
  IconLanguage,
} from "@tabler/icons-react";
import { usePreferencesStore } from "../../store/usePreferencesStore";
import { useTranslation } from "../../i18n";
import {
  LANGUAGE_LABELS,
  SUPPORTED_LANGUAGES,
  normalizeLanguage,
} from "../../i18n/locales";

interface AppearanceCardProps {
  colorScheme: "light" | "dark" | "auto";
  setColorScheme: (value: "light" | "dark" | "auto") => void;
}

export function AppearanceCard({ colorScheme, setColorScheme }: AppearanceCardProps) {
  const tableDensity = usePreferencesStore((state) => state.tableDensity);
  const setTableDensity = usePreferencesStore((state) => state.setTableDensity);
  const language = usePreferencesStore((state) => state.language);
  const setLanguage = usePreferencesStore((state) => state.setLanguage);
  const { t } = useTranslation();
  const languageOptions = SUPPORTED_LANGUAGES.map((value) => ({
    value,
    label: LANGUAGE_LABELS[value],
  }));
  return (
    <Card withBorder padding="xl" radius="lg" shadow="xs">
      <Stack gap="lg">
        <Group gap="md">
          <Paper p="xs" radius="md" bg="violet.6">
            <IconPalette size={20} color="white" />
          </Paper>
          <div>
            <Title order={4} fw={700}>
              {t("appearance.title")}
            </Title>
            <Text c="dimmed" size="xs">
              {t("appearance.description")}
            </Text>
          </div>
        </Group>
        <Stack gap="xs">
          <Text size="sm" fw={700}>
            {t("appearance.themeMode")}
          </Text>
          <SegmentedControl
            value={colorScheme}
            onChange={(value: "light" | "dark" | "auto") => setColorScheme(value)}
            data={[
              {
                value: "light",
                label: (
                  <Center style={{ gap: 10 }}>
                    <IconSun size={16} />
                    <span>{t("appearance.theme.light")}</span>
                  </Center>
                ),
              },
              {
                value: "dark",
                label: (
                  <Center style={{ gap: 10 }}>
                    <IconMoon size={16} />
                    <span>{t("appearance.theme.dark")}</span>
                  </Center>
                ),
              },
              {
                value: "auto",
                label: (
                  <Center style={{ gap: 10 }}>
                    <IconDeviceDesktop size={16} />
                    <span>{t("appearance.theme.system")}</span>
                  </Center>
                ),
              },
            ]}
            radius="md"
            size="md"
            fullWidth
          />
        </Stack>
        <Stack gap="xs">
          <Text size="sm" fw={700}>
            {t("appearance.tableDensity")}
          </Text>
          <Text c="dimmed" size="xs">
            {t("appearance.tableDensity.description")}
          </Text>
          <SegmentedControl
            value={tableDensity}
            onChange={(value) =>
              setTableDensity(value as "comfortable" | "compact")
            }
            data={[
              {
                value: "comfortable",
                label: (
                  <Center style={{ gap: 10 }}>
                    <IconBaselineDensityMedium size={16} />
                    <span>{t("appearance.density.comfortable")}</span>
                  </Center>
                ),
              },
              {
                value: "compact",
                label: (
                  <Center style={{ gap: 10 }}>
                    <IconBaselineDensitySmall size={16} />
                    <span>{t("appearance.density.compact")}</span>
                  </Center>
                ),
              },
            ]}
            radius="md"
            size="md"
            fullWidth
          />
        </Stack>
        <Stack gap="xs">
          <Text size="sm" fw={700}>
            {t("common.language")}
          </Text>
          <Text c="dimmed" size="xs">
            {t("appearance.language.description")}
          </Text>
          <Select
            value={language}
            onChange={(value) => setLanguage(normalizeLanguage(value))}
            data={languageOptions}
            leftSection={<IconLanguage size={16} />}
            allowDeselect={false}
            radius="md"
            aria-label={t("common.language")}
          />
        </Stack>
      </Stack>
    </Card>
  );
}
