import {
  Paper,
  Title,
  Text,
  Stack,
  Tabs,
  Code,
  ScrollArea,
  List,
  Table,
  ThemeIcon,
  Anchor,
} from "@mantine/core";
import { IconMail, IconBook2, IconSettings } from "@tabler/icons-react";
import ReactMarkdown from "react-markdown";
import readmeContent from "../../docs/README.md?raw";
import emailBackendSetup from "../../docs/email-backend-setup.md?raw";
import servicesContent from "../../docs/services.md?raw";

const docs = [
  { id: "intro", label: "Introduction", icon: IconBook2, content: readmeContent },
  { id: "email-backend", label: "Email Backend (SMTP, IMAP, POP3)", icon: IconMail, content: emailBackendSetup },
  { id: "running-service", label: "Running as a Service", icon: IconSettings, content: servicesContent },
];

export default function DocsPage() {
  return (
    <Stack gap="md">
      <div>
        <Title order={3}>Documentation</Title>
        <Text size="sm" c="dimmed">
          Setup guides and configuration references
        </Text>
      </div>

      <Tabs defaultValue="intro">
        <Tabs.List>
          {docs.map((d) => {
            const Icon = d.icon;
            return (
              <Tabs.Tab key={d.id} value={d.id} leftSection={<Icon size={16} />}>
                {d.label}
              </Tabs.Tab>
            );
          })}
        </Tabs.List>

        {docs.map((d) => (
          <Tabs.Panel key={d.id} value={d.id} pt="md">
            <Paper withBorder p="lg" radius="md">
              <ScrollArea.Autosize mah="calc(100vh - 280px)">
                <ReactMarkdown
                  components={{
                    h1: ({ children }) => (
                      <Title order={2} mb="sm" mt="lg">
                        {children}
                      </Title>
                    ),
                    h2: ({ children }) => (
                      <Title order={4} mb="xs" mt="md">
                        {children}
                      </Title>
                    ),
                    h3: ({ children }) => (
                      <Title order={5} mb="xs" mt="sm">
                        {children}
                      </Title>
                    ),
                    p: ({ children }) => (
                      <Text size="sm" mb="xs">
                        {children}
                      </Text>
                    ),
                    ul: ({ children }) => (
                      <List
                        size="sm"
                        spacing="xs"
                        icon={
                          <ThemeIcon size={20} radius="xl" variant="light">
                            •
                          </ThemeIcon>
                        }
                        mb="sm"
                      >
                        {children}
                      </List>
                    ),
                    ol: ({ children }) => (
                      <List
                        type="ordered"
                        size="sm"
                        spacing="xs"
                        mb="sm"
                      >
                        {children}
                      </List>
                    ),
                    li: ({ children }) => <List.Item>{children}</List.Item>,
                    code: ({ children, className }) =>
                      className ? (
                        <Code block mb="sm" mt="xs">
                          {String(children).replace(/\n$/, "")}
                        </Code>
                      ) : (
                        <Code>{children}</Code>
                      ),
                    pre: ({ children }) => <>{children}</>,
                    table: ({ children }) => (
                      <Table
                        withTableBorder
                        withColumnBorders
                        striped
                        highlightOnHover
                        mb="md"
                        mt="xs"
                      >
                        {children}
                      </Table>
                    ),
                    thead: ({ children }) => <Table.Thead>{children}</Table.Thead>,
                    tbody: ({ children }) => <Table.Tbody>{children}</Table.Tbody>,
                    tr: ({ children }) => <Table.Tr>{children}</Table.Tr>,
                    th: ({ children }) => <Table.Th>{children}</Table.Th>,
                    td: ({ children }) => <Table.Td>{children}</Table.Td>,
                    a: ({ href, children }) => (
                      <Anchor href={href} target="_blank" rel="noopener noreferrer" size="sm">
                        {children}
                      </Anchor>
                    ),
                  }}
                >
                  {d.content}
                </ReactMarkdown>
              </ScrollArea.Autosize>
            </Paper>
          </Tabs.Panel>
        ))}
      </Tabs>
    </Stack>
  );
}
