// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

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
import { useState, type ReactNode } from "react";
import { IconMail, IconBook2, IconSettings, IconShieldLock, IconPlugConnected } from "@tabler/icons-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { GUIDES, guideIdForHref, isExternalHref } from "../components/docs/guides";

const ICONS: Record<string, typeof IconBook2> = {
  "management-entrypoint": IconShieldLock,
  "email-backend": IconMail,
  "running-service": IconSettings,
  "websockets-sse": IconPlugConnected,
};

/**
 * GuideLink renders a link in a guide. A link to another guide opens its tab:
 * the guides link to each other as files, which the gateway does not serve, so
 * followed as links they opened a window reading "Not Found". A link to another
 * site opens in a new tab without handing it this page. Anything else would be
 * a dead link, so it is shown as text.
 */
function GuideLink({ href, children, onGuide }: { href?: string; children: ReactNode; onGuide: (id: string) => void }) {
  const guide = guideIdForHref(href);
  if (guide) {
    return (
      <Anchor component="button" type="button" size="sm" onClick={() => onGuide(guide)}>
        {children}
      </Anchor>
    );
  }
  if (isExternalHref(href)) {
    return (
      <Anchor href={href} target="_blank" rel="noopener noreferrer" size="sm">
        {children}
      </Anchor>
    );
  }
  return <>{children}</>;
}

export default function DocsPage() {
  const [active, setActive] = useState<string | null>("intro");
  return (
    <Stack gap="md">
      <div>
        <Title order={3}>Documentation</Title>
        <Text size="sm" c="dimmed">
          Setup guides and configuration references
        </Text>
      </div>

      <Tabs value={active} onChange={setActive}>
        <Tabs.List>
          {GUIDES.map((d) => {
            const Icon = ICONS[d.id] ?? IconBook2;
            return (
              <Tabs.Tab key={d.id} value={d.id} leftSection={<Icon size={16} />}>
                {d.label}
              </Tabs.Tab>
            );
          })}
        </Tabs.List>

        {GUIDES.map((d) => (
          <Tabs.Panel key={d.id} value={d.id} pt="md">
            <Paper withBorder p="lg" radius="md">
              <ScrollArea.Autosize mah="calc(100vh - 280px)">
                <ReactMarkdown
                  remarkPlugins={[remarkGfm]}
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
                      <GuideLink href={href} onGuide={setActive}>
                        {children}
                      </GuideLink>
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
