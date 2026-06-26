import React, { useMemo, useState, useCallback } from "react";
import {
  ReactFlow,
  Panel,
  useNodesState,
  useEdgesState,
  Handle,
  Position,
  Background,
  Controls,
  MiniMap,
  ConnectionLineType,
  MarkerType,
  ReactFlowProvider,
  useReactFlow,
} from "@xyflow/react";
import type { Edge, Node, NodeProps, NodeMouseHandler } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Paper,
  Text,
  Group,
  ThemeIcon,
  Badge,
  Stack,
  useMantineColorScheme,
  Box,
  SegmentedControl,
} from "@mantine/core";
import {
  IconNetwork,
  IconRoute,
  IconShield,
  IconServer,
  IconDatabase,
  IconAlertCircle,
} from "@tabler/icons-react";
import dagre from "dagre";
import {
  type Route,
  type Service,
  type EntryPoint,
  type Middleware,
  EntryPointType,
} from "../types/gateon";

const nodeWidth = 220;
const nodeHeight = 80;

type TopologyNodeType = "entrypoint" | "route" | "middleware" | "service" | "target";

interface TopologyNodeData {
  label: string;
  sublabel?: string;
  badge?: string;
  [key: string]: unknown;
}

type TopologyNode = Node<TopologyNodeData, TopologyNodeType>;

type LayoutDirection = "LR" | "TB";

// Single source of truth for per-type colors, shared by the node border, the
// legend, and the minimap so they never drift apart.
const NODE_COLORS: Record<TopologyNodeType, string> = {
  entrypoint: "blue",
  route: "orange",
  middleware: "grape",
  service: "teal",
  target: "cyan",
};

const nodeColorVar = (type?: string) =>
  `var(--mantine-color-${NODE_COLORS[type as TopologyNodeType] ?? "gray"}-filled)`;

// Theme-aware edge stroke colors (the `-filled` token adapts to light/dark),
// keyed by the kind of transition so the graph stays legible in both themes.
const EDGE_STROKE = {
  epToRoute: "var(--mantine-color-blue-filled)",
  middleware: "var(--mantine-color-grape-filled)",
  toService: "var(--mantine-color-teal-filled)",
  toTarget: "var(--mantine-color-cyan-filled)",
} as const;

const LEGEND: { type: TopologyNodeType; label: string }[] = [
  { type: "entrypoint", label: "Entrypoint" },
  { type: "route", label: "Route" },
  { type: "middleware", label: "Middleware" },
  { type: "service", label: "Service" },
  { type: "target", label: "Backend Target" },
];

const getLayoutedElements = (
  nodes: TopologyNode[],
  edges: Edge[],
  direction: LayoutDirection = "LR",
) => {
  const isHorizontal = direction === "LR";
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));
  dagreGraph.setGraph({ rankdir: direction });

  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: nodeWidth, height: nodeHeight });
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  const layoutedNodes = nodes.map((node) => {
    const nodeWithPosition = dagreGraph.node(node.id);
    if (!nodeWithPosition) return node;

    return {
      ...node,
      // CustomNode reads this to place its handles along the flow axis.
      data: { ...node.data, isHorizontal },
      targetPosition: isHorizontal ? Position.Left : Position.Top,
      sourcePosition: isHorizontal ? Position.Right : Position.Bottom,
      position: {
        x: nodeWithPosition.x - nodeWidth / 2,
        y: nodeWithPosition.y - nodeHeight / 2,
      },
      width: nodeWidth,
      height: nodeHeight,
    };
  });

  return { nodes: layoutedNodes, edges };
};

const CustomNode = React.memo(({ data, type }: NodeProps<TopologyNode>) => {
  const { colorScheme } = useMantineColorScheme();
  const isDark = colorScheme === "dark";
  const handleColor = isDark ? "var(--mantine-color-dark-3)" : "#adb5bd";
  const isHorizontal = data.isHorizontal !== false;
  const targetPos = isHorizontal ? Position.Left : Position.Top;
  const sourcePos = isHorizontal ? Position.Right : Position.Bottom;

  const getIcon = () => {
    switch (type) {
      case "entrypoint":
        return <IconNetwork size={18} />;
      case "route":
        return <IconRoute size={18} />;
      case "middleware":
        return <IconShield size={18} />;
      case "service":
        return <IconServer size={18} />;
      case "target":
        return <IconDatabase size={18} />;
      default:
        return null;
    }
  };

  const getColor = () => NODE_COLORS[type as TopologyNodeType] ?? "gray";

  return (
    <Paper
      withBorder
      shadow="md"
      p="xs"
      radius="md"
      style={{
        width: nodeWidth,
        minHeight: nodeHeight,
        background: isDark ? "var(--mantine-color-dark-7)" : "white",
        borderColor: `var(--mantine-color-${getColor()}-filled)`,
        borderWidth: 2,
      }}
    >
      <Handle type="target" position={targetPos} style={{ background: handleColor }} />
      <Group wrap="nowrap" gap="xs">
        <ThemeIcon color={getColor()} variant="light" size="lg">
          {getIcon()}
        </ThemeIcon>
        <Box style={{ overflow: "hidden" }}>
          <Text size="sm" fw={700} truncate>
            {data.label}
          </Text>
          {data.sublabel && (
            <Text size="xs" c="dimmed" truncate>
              {data.sublabel}
            </Text>
          )}
          {data.badge && (
            <Badge size="xs" variant="outline" mt={4}>
              {data.badge}
            </Badge>
          )}
        </Box>
      </Group>
      <Handle type="source" position={sourcePos} style={{ background: handleColor }} />
    </Paper>
  );
});
CustomNode.displayName = "TopologyCustomNode";

const nodeTypes = {
  entrypoint: CustomNode,
  route: CustomNode,
  middleware: CustomNode,
  service: CustomNode,
  target: CustomNode,
};

interface TopologyGraphProps {
  entrypoints: EntryPoint[];
  routes: Route[];
  middlewares: Middleware[];
  services: Service[];
}

export const TopologyGraph: React.FC<TopologyGraphProps> = (props) => (
  <ReactFlowProvider>
    <TopologyGraphInner {...props} />
  </ReactFlowProvider>
);

const TopologyGraphInner: React.FC<TopologyGraphProps> = ({
  entrypoints,
  routes,
  middlewares,
  services,
}) => {
  const { fitView } = useReactFlow();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [direction, setDirection] = useState<LayoutDirection>("LR");
  const { nodes: initialNodes, edges: initialEdges } = useMemo(() => {
    const nodes: TopologyNode[] = [];
    const edges: Edge[] = [];
    // Services can be referenced by many routes; their node + target subgraph
    // must be emitted exactly once, otherwise React Flow sees duplicate ids.
    const emittedServices = new Set<string>();

    // 1. Add Entrypoints
    (entrypoints || []).forEach((ep) => {
      if (!ep) return;
      nodes.push({
        id: `ep-${ep.id}`,
        type: "entrypoint",
        data: {
          label: ep.name || ep.id,
          sublabel: ep.address,
          badge: EntryPointType[ep.type],
        },
        position: { x: 0, y: 0 },
      });
    });

    // 2. Add Routes and link to Entrypoints
    (routes || []).forEach((r) => {
      if (!r) return;

      nodes.push({
        id: `route-${r.id}`,
        type: "route",
        data: {
          label: r.name || r.id,
          sublabel: r.rule,
          badge: (r.type || "").toUpperCase(),
        },
        position: { x: 0, y: 0 },
      });

      // Link entrypoints to routes
      const relevantEps = (entrypoints || []).filter((ep) => {
        if (!ep) return false;
        const epIdMatch = Array.isArray(r.entrypoints) && r.entrypoints.includes(ep.id);
        const allEntries = !Array.isArray(r.entrypoints) || r.entrypoints.length === 0;

        if (ep.type === EntryPointType.TCP || ep.type === EntryPointType.UDP) {
          const typeMatch =
            (ep.type === EntryPointType.TCP && r.type === "tcp") ||
            (ep.type === EntryPointType.UDP && r.type === "udp");
          return epIdMatch && typeMatch;
        }

        const isWebCompatible = ["http", "grpc", "graphql"].includes(r.type || "");
        return (epIdMatch || allEntries) && isWebCompatible;
      });

      relevantEps.forEach((ep) => {
        edges.push({
          id: `e-ep-${ep.id}-r-${r.id}`,
          source: `ep-${ep.id}`,
          target: `route-${r.id}`,
          animated: true,
          style: { stroke: EDGE_STROKE.epToRoute },
        });
      });

      // 3. Add Middlewares for this route
      let lastMiddlewareId = `route-${r.id}`;
      if (Array.isArray(r.middlewares) && r.middlewares.length > 0) {
        r.middlewares.forEach((mwId, idx) => {
          const mw = (middlewares || []).find((m) => m?.id === mwId);
          if (mw) {
            const nodeId = `route-${r.id}-mw-${mwId}-${idx}`;
            nodes.push({
              id: nodeId,
              type: "middleware",
              data: {
                label: mw.name || mw.id,
                sublabel: mw.type,
              },
              position: { x: 0, y: 0 },
            });

            edges.push({
              id: `e-${lastMiddlewareId}-${nodeId}`,
              source: lastMiddlewareId,
              target: nodeId,
              animated: true,
              style: { stroke: EDGE_STROKE.middleware },
            });
            lastMiddlewareId = nodeId;
          }
        });
      }

      // 4. Link to Service
      const svc = (services || []).find((s) => s?.id === r.service_id);
      if (svc) {
        const svcNodeId = `svc-${svc.id}`;

        // The service node and its backend targets are shared across every
        // route that points at this service, so emit them only once.
        if (!emittedServices.has(svc.id)) {
          emittedServices.add(svc.id);

          nodes.push({
            id: svcNodeId,
            type: "service",
            data: {
              label: svc.name || svc.id,
              sublabel: `${svc.weighted_targets?.length || 0} targets`,
            },
            position: { x: 0, y: 0 },
          });

          // 5. Add targets for service
          if (Array.isArray(svc.weighted_targets)) {
            svc.weighted_targets.forEach((target, tIdx) => {
              if (!target) return;
              const targetNodeId = `svc-${svc.id}-t-${tIdx}`;
              nodes.push({
                id: targetNodeId,
                type: "target",
                data: {
                  label: target.url,
                  sublabel: `Weight: ${target.weight}`,
                },
                position: { x: 0, y: 0 },
              });

              edges.push({
                id: `e-svc-${svc.id}-t-${tIdx}`,
                source: svcNodeId,
                target: targetNodeId,
                animated: true,
                style: { stroke: EDGE_STROKE.toTarget },
              });
            });
          }
        }

        // The route -> service edge is per-route (its id embeds the route id
        // via lastMiddlewareId), so it is always safe to add here.
        edges.push({
          id: `e-${lastMiddlewareId}-svc-${svc.id}`,
          source: lastMiddlewareId,
          target: svcNodeId,
          animated: true,
          style: { stroke: EDGE_STROKE.toService },
        });
      }
    });

    return getLayoutedElements(nodes, edges, direction);
  }, [entrypoints, routes, middlewares, services, direction]);

  // Per-type node counts for the legend summary.
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    initialNodes.forEach((n) => {
      const t = n.type ?? "unknown";
      c[t] = (c[t] ?? 0) + 1;
    });
    return c;
  }, [initialNodes]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Sync state when data changes, then re-fit once the new nodes are painted.
  // Two rAFs guarantee layout has flushed before fitView measures, which is
  // more reliable than guessing a setTimeout delay.
  React.useEffect(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
    setSelectedId(null);
    let raf2 = 0;
    const raf1 = requestAnimationFrame(() => {
      raf2 = requestAnimationFrame(() => fitView({ duration: 400 }));
    });
    return () => {
      cancelAnimationFrame(raf1);
      cancelAnimationFrame(raf2);
    };
  }, [initialNodes, initialEdges, setNodes, setEdges, fitView]);

  // When a node is selected, highlight the edges touching it and dim the rest
  // so the operator can trace a single flow through the graph.
  const neighborIds = useMemo(() => {
    if (!selectedId) return null;
    const ids = new Set<string>([selectedId]);
    edges.forEach((e) => {
      if (e.source === selectedId) ids.add(e.target);
      else if (e.target === selectedId) ids.add(e.source);
    });
    return ids;
  }, [selectedId, edges]);

  const displayNodes = useMemo(() => {
    if (!neighborIds) return nodes;
    return nodes.map((n) => ({
      ...n,
      style: { ...n.style, opacity: neighborIds.has(n.id) ? 1 : 0.2 },
    }));
  }, [nodes, neighborIds]);

  const displayEdges = useMemo(() => {
    if (!selectedId) return edges;
    return edges.map((e) => {
      const connected = e.source === selectedId || e.target === selectedId;
      return {
        ...e,
        animated: connected,
        style: {
          ...e.style,
          opacity: connected ? 1 : 0.12,
          strokeWidth: connected ? 2.5 : 1,
        },
      };
    });
  }, [edges, selectedId]);

  const onNodeClick = useCallback<NodeMouseHandler>((_, node) => {
    setSelectedId((prev) => (prev === node.id ? null : node.id));
  }, []);

  const onPaneClick = useCallback(() => setSelectedId(null), []);

  if (nodes.length === 0) {
    return (
      <Box h="calc(100vh - 250px)" style={{ border: "1px solid var(--mantine-color-gray-3)", borderRadius: "var(--mantine-radius-md)", display: "flex", alignItems: "center", justifyContent: "center" }}>
        <Stack align="center" gap="sm">
          <ThemeIcon size="xl" radius="md" color="gray" variant="light">
            <IconAlertCircle size={30} />
          </ThemeIcon>
          <Text fw={500} c="dimmed">No traffic topology data available</Text>
          <Text size="sm" c="dimmed" ta="center" maw={400}>
            Configure entrypoints and routes to see how traffic flows through your Gateon instance.
          </Text>
        </Stack>
      </Box>
    );
  }

  return (
    <Box h="calc(100vh - 250px)" style={{ border: "1px solid var(--mantine-color-gray-3)", borderRadius: "var(--mantine-radius-md)", overflow: "hidden" }}>
      <ReactFlow
        nodes={displayNodes}
        edges={displayEdges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        onPaneClick={onPaneClick}
        nodeTypes={nodeTypes}
        fitView
        connectionLineType={ConnectionLineType.SmoothStep}
        defaultEdgeOptions={{
          type: "smoothstep",
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: "var(--mantine-color-gray-5)",
          },
        }}
      >
        <Background />
        <Controls />
        <MiniMap
          pannable
          zoomable
          nodeColor={(n) => nodeColorVar(n.type)}
          nodeStrokeWidth={2}
          style={{ background: "var(--mantine-color-body)" }}
        />
        <Panel position="top-left">
          <Paper p={4} withBorder shadow="sm" radius="md">
            <SegmentedControl
              size="xs"
              value={direction}
              onChange={(v) => setDirection(v as LayoutDirection)}
              data={[
                { label: "Horizontal", value: "LR" },
                { label: "Vertical", value: "TB" },
              ]}
            />
          </Paper>
        </Panel>
        <Panel position="top-right">
          <Paper p="xs" withBorder shadow="sm" radius="md">
            <Stack gap={4}>
              {LEGEND.map(({ type, label }) => (
                <Group key={type} gap="xs" justify="space-between" wrap="nowrap">
                  <Group gap="xs" wrap="nowrap">
                    <Box w={12} h={12} bg={NODE_COLORS[type]} style={{ borderRadius: "50%" }} />
                    <Text size="xs">{label}</Text>
                  </Group>
                  <Badge size="xs" variant="light" color={NODE_COLORS[type]}>
                    {counts[type] ?? 0}
                  </Badge>
                </Group>
              ))}
            </Stack>
          </Paper>
        </Panel>
      </ReactFlow>
    </Box>
  );
};
