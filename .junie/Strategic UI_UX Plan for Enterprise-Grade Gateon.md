### Strategic UI/UX Plan for Enterprise-Grade Gateon

To elevate Gateon to an enterprise-grade solution while maintaining ease of use, we will focus on Modernizing the Dashboard, Robust Route Management, and Actionable Observability.

### 1. Dashboard & Navigation (The "Command Center")
The current single-page vertical stack will be replaced with a structured layout that supports growth and high-density information.
- Sidebar Navigation: Implement a collapsible sidebar for quick access to `Dashboard`, `Routes`, `Certificates`, `Logs`, and `Settings`.
- Global Health Bar: A sticky top header displaying real-time aggregated metrics (Request/sec, Error Rate, Active Connections) across all routes.
- Service Overview: A grid of status cards representing different clusters or environments (Production, Staging).

### 2. Enterprise Route Management
Managing high volumes of routes requires more than a simple list.
- Search & Filtering: Add a powerful filter bar to search routes by ID, host, path, or tags. Support filtering by "Healthy/Unhealthy" or "Type" (gRPC vs HTTP).
- Paginated Table View: Move from cards to a high-density table for listing routes, with "Actions" (Edit, Clone, Delete, Pause) grouped clearly.
- Wizard-based Route Creation: Replace the large `RouteForm` with a multi-step wizard:
  1. Basics: ID, Type, Host/Path.
  2. Upstream: Targets, Weights, Load Balancing Policy.
  3. Security: JWT/API-Key configuration.
  4. Resiliency: Circuit Breaker, Retries, and Timeouts.
- Configuration Preview: A side-by-side JSON/YAML preview of the route as you build it in the UI.

### 3. Advanced Observability (Actionable Insights)
Enterprise users need to know why things are failing, not just that they are.
- Rich Metrics Visualizations: Integrate small sparkline charts for latency and error rates within each route entry.
- Log Filtering: Upgrade `LiveLogs` to support searching and filtering by `RouteID`, `Status Code`, or `Client IP`.
- Circuit Breaker Dashboard: A dedicated view showing which circuits are currently `OPEN` or `HALF-OPEN` with a history of when they tripped.

### 4. Enterprise Hardening & DX
- Role-Based Access (Future): Placeholder UI for User management and API Keys for the Gateway's own control plane.
- Dark/Light Mode: Full support for system-preferred color schemes via Mantine.
- Lazy Loading Everything: Ensuring that route-level components and heavy charting libraries are only loaded when needed to keep the initial dashboard light.

### 5. Implementation Roadmap (Immediate Steps)
1. Refactor `App.tsx`: Introduce `@tanstack/react-router` and a `Shell` component with a sidebar.
2. Modularize `RouteForm`: Break the 200-line form into logical sub-components (`UpstreamConfig`, `SecurityConfig`, etc.).
3. DataTable Implementation: Replace `RouteList` cards with a searchable table.
4. Polish `LiveLogs`: Add "Pause" and "Clear" functionality with basic text filtering.
