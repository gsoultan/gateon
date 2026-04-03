import React, { useMemo, useCallback } from "react";
import {
  ReactFlow,
  Panel,
  useNodesState,
  useEdgesState,
  Handle,
  Position,
  Background,
  Controls,
  ConnectionLineType,
  MarkerType,
  ReactFlowProvider,
  useReactFlow,
} from "@xyflow/react";
import type { Edge, Node } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Paper,
  Text,
  Group,
  ThemeIcon,
  Badge,
  Stack,
  useMantineTheme,
  useMantineColorScheme,
  Box,
  Center,
  Button,
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

const getLayoutedElements = (nodes: Node[], edges: Edge[], direction = "LR") => {
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

const CustomNode = ({ data, type }: any) => {
  const theme = useMantineTheme();
  const { colorScheme } = useMantineColorScheme();
  const isDark = colorScheme === "dark";

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

  const getColor = () => {
    switch (type) {
      case "entrypoint":
        return "blue";
      case "route":
        return "orange";
      case "middleware":
        return "grape";
      case "service":
        return "teal";
      case "target":
        return "cyan";
      default:
        return "gray";
    }
  };

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
      <Handle type="target" position={Position.Left} style={{ background: "#555" }} />
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
      <Handle type="source" position={Position.Right} style={{ background: "#555" }} />
    </Paper>
  );
};

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
  const { nodes: initialNodes, edges: initialEdges } = useMemo(() => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];

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
          style: { stroke: "#228be6" },
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
              style: { stroke: "#be4bdb" },
            });
            lastMiddlewareId = nodeId;
          }
        });
      }

      // 4. Link to Service
      const svc = (services || []).find((s) => s?.id === r.service_id);
      if (svc) {
        const svcNodeId = `svc-${svc.id}`;
        // Ensure service node is only added once
        if (!nodes.find((n) => n.id === svcNodeId)) {
          nodes.push({
            id: svcNodeId,
            type: "service",
            data: {
              label: svc.name || svc.id,
              sublabel: `${svc.weighted_targets?.length || 0} targets`,
            },
            position: { x: 0, y: 0 },
          });
        }

        edges.push({
          id: `e-${lastMiddlewareId}-svc-${svc.id}`,
          source: lastMiddlewareId,
          target: svcNodeId,
          animated: true,
          style: { stroke: "#0ca678" },
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
                    label: target.target || (target as any).url, // handle potential target/url mismatch
                    sublabel: `Weight: ${target.weight}`,
                },
                position: { x: 0, y: 0 },
            });

            edges.push({
                id: `e-svc-${svc.id}-t-${tIdx}`,
                source: svcNodeId,
                target: targetNodeId,
                animated: true,
                style: { stroke: "#1098ad" },
            });
          });
        }
      }
    });

    return getLayoutedElements(nodes, edges);
  }, [entrypoints, routes, middlewares, services]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Sync state when data changes
  React.useEffect(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
    // Request fitView on next tick to ensure nodes are rendered
    setTimeout(() => fitView({ duration: 400 }), 50);
  }, [initialNodes, initialEdges, setNodes, setEdges, fitView]);

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
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        fitView
        connectionLineType={ConnectionLineType.SmoothStep}
        defaultEdgeOptions={{
          type: "smoothstep",
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: "#bbb",
          },
        }}
      >
        <Background />
        <Controls />
        <Panel position="top-right">
          <Paper p="xs" withBorder shadow="sm" radius="md">
            <Stack gap={4}>
              <Group gap="xs">
                <Box w={12} h={12} bg="blue" style={{ borderRadius: "50%" }} />
                <Text size="xs">Entrypoint</Text>
              </Group>
              <Group gap="xs">
                <Box w={12} h={12} bg="orange" style={{ borderRadius: "50%" }} />
                <Text size="xs">Route</Text>
              </Group>
              <Group gap="xs">
                <Box w={12} h={12} bg="grape" style={{ borderRadius: "50%" }} />
                <Text size="xs">Middleware</Text>
              </Group>
              <Group gap="xs">
                <Box w={12} h={12} bg="teal" style={{ borderRadius: "50%" }} />
                <Text size="xs">Service</Text>
              </Group>
              <Group gap="xs">
                <Box w={12} h={12} bg="cyan" style={{ borderRadius: "50%" }} />
                <Text size="xs">Backend Target</Text>
              </Group>
            </Stack>
          </Paper>
        </Panel>
      </ReactFlow>
    </Box>
  );
};
