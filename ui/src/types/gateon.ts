export type LimitStats = {
  rate_limit_rejected: Record<string, number>;
  inflight_rejected: Record<string, number>;
  buffering_rejected: Record<string, number>;
};

export type MiddlewarePresetItem = {
  type: string;
  name: string;
  config: Record<string, string>;
};

export type MiddlewarePreset = {
  id: string;
  name: string;
  description: string;
  middlewares: MiddlewarePresetItem[];
};

export type PathStats = {
  host: string;
  path: string;
  request_count: number;
  latency_sum_seconds: number;
  avg_latency_seconds: number;
};

export type TargetStats = {
  url: string;
  alive: boolean;
  request_count: number;
  error_count: number;
  avg_latency_ms: number;
  active_conn: number;
  circuit_state?: string;
  status_codes?: Record<string, number>;
};

export type Target = {
  url: string;
  weight: number;
  /** For HTTP: "http" | "https"; for gRPC: "h2" | "h2c" */
  protocol?: string;
};

export type TlsClientConfig = {
  enabled: boolean;
  cert_file?: string;
  key_file?: string;
  ca_file?: string;
  skip_verify?: boolean;
  server_name?: string;
};

export type Service = {
  id: string;
  name: string;
  weighted_targets: Target[];
  load_balancer_policy: string;
  health_check_path: string;
  backend_type?: "http" | "grpc" | "graphql" | "tcp" | "udp";
  l4_health_check_interval_ms?: number;
  l4_health_check_timeout_ms?: number;
  l4_udp_session_timeout_s?: number;
  l4_proxy_protocol?: boolean;
  discovery_url?: string;
  tls_client_config?: TlsClientConfig;
  /** Overrides the target port for health checks (e.g. HTTP health on port 3001 while gRPC runs on 3000). */
  health_check_port?: number;
  /** Overrides the scheme for health checks (e.g. "http", "https"). */
  health_check_protocol?: string;
};

export type RouteTLSConfig = {
  certificate_ids: string[];
  option_id?: string;
};

export type TLSOption = {
  id: string;
  name: string;
  min_tls_version?: string;
  max_tls_version?: string;
  cipher_suites?: string[];
  prefer_server_cipher_suites?: boolean;
  client_auth_type?: string;
  sni_strict?: boolean;
  alpn_protocols?: string[];
  client_authority_ids?: string[];
};

export type Route = {
  id: string;
  name?: string;
  type: "http" | "grpc" | "graphql" | "tcp" | "udp";
  entrypoints: string[];
  rule: string;
  priority: number;
  middlewares: string[];
  service_id: string;
  tls?: RouteTLSConfig;
  disabled?: boolean;
};

export type StatusResponse = {
  status: string;
  version: string;
  uptime: number;
  memory_usage: number;
  routes_count: number;
  services_count: number;
  entry_points_count: number;
  middlewares_count: number;
};

export type Certificate = {
  id: string;
  name: string;
  cert_file: string;
  key_file: string;
  /** Optional CA/intermediate certificate file appended to the served chain during SNI selection. */
  ca_file?: string;
  host?: string;
};

export type ClientAuthority = {
  id: string;
  name: string;
  ca_file: string;
  /** Optional per-CA preferred client auth mode; UI hint, may be enforced by server config */
  client_auth_type?: string;
};

export type AcmeConfig = {
  enabled: boolean;
  email?: string;
  ca_server?: string;
  challenge_type?: string;
  dns_provider?: string;
  dns_config?: Record<string, string>;
};

export type TlsConfig = {
  enabled: boolean;
  email?: string;
  domains?: string[];
  auto_redirect?: boolean;
  min_tls_version?: string;
  max_tls_version?: string;
  client_auth_type?: string;
  cipher_suites?: string[];
  certificates?: Certificate[];
  client_authorities?: ClientAuthority[];
  acme?: AcmeConfig;
};

export type RedisConfig = {
  enabled?: boolean;
  addr?: string;
  password?: string;
  db?: number;
};

export type OtelConfig = {
  enabled?: boolean;
  endpoint?: string;
  service_name?: string;
};

export type LogConfig = {
  level?: "debug" | "info" | "warn" | "error";
  development?: boolean;
  format?: "json" | "text";
  path_stats_retention_days?: number;
};

export type TransportConfig = {
  max_idle_conns?: number;
  max_idle_conns_per_host?: number;
  idle_conn_timeout_seconds?: number;
};

export type DatabaseConfig = {
  driver?: "sqlite" | "postgres" | "mysql" | "mariadb";
  sqlite_path?: string;
  host?: string;
  port?: number;
  user?: string;
  password?: string;
  database?: string;
  ssl_mode?: string;
};

export type AuthConfig = {
  enabled?: boolean;
  paseto_secret?: string;
  /** @deprecated Use database_config or database_url. */
  sqlite_path?: string;
  /** Fallback connection string (encrypted when GATEON_ENCRYPTION_KEY is set) */
  database_url?: string;
  database_config?: DatabaseConfig;
};

export type User = {
  id: string;
  username: string;
  password?: string;
  role: "admin" | "operator" | "viewer";
};

export type LoginResponse = {
  token: string;
  user: User;
};

export type IsSetupRequiredResponse = {
  required: boolean;
};

export type SetupRequest = {
  admin_username: string;
  admin_password: string;
  paseto_secret: string;
  management_bind: string;
  management_port: string;
  // Optional for first-run wizard database selection
  database_url?: string;
  database_config?: DatabaseConfig;
};

export type SetupResponse = {
  success: boolean;
  error?: string;
};

export type Middleware = {
  id: string;
  name: string;
  type: string;
  config: Record<string, string>;
  wasm_blob?: string; // base64 encoded
};

export type WafConfig = {
  enabled: boolean;
  use_crs: boolean;
  paranoia_level: number;
  custom_directives?: string;
};

export type HaConfig = {
  enabled?: boolean;
  interface?: string;
  virtual_router_id?: number;
  priority?: number;
  virtual_ips?: string[];
  advert_int?: number;
  auth_pass?: string;
};

export type AnomalyDetectionConfig = {
  enabled?: boolean;
  prometheus_url?: string;
  check_interval_seconds?: number;
  sensitivity?: number;
};

export type EbpfConfig = {
  enabled?: boolean;
  xdp_rate_limit?: boolean;
  tc_filtering?: boolean;
};

export type GlobalConfig = {
  tls?: TlsConfig;
  redis?: RedisConfig;
  otel?: OtelConfig;
  log?: LogConfig;
  auth?: AuthConfig;
  transport?: TransportConfig;
  waf?: WafConfig;
  ha?: HaConfig;
  anomaly_detection?: AnomalyDetectionConfig;
  ebpf?: EbpfConfig;
  management?: ManagementConfig;
};

export type ManagementConfig = {
  bind?: string;
  port?: string;
  allowed_ips?: string[];
};

export enum EntryPointType {
  HTTP = 0,
  GRPC = 1,
  TCP = 2,
  UDP = 3,
  HTTP2 = 4,
  HTTP3 = 5,
}

export enum Protocol {
  TCP = 0,
  UDP = 1,
}

export type EntryPoint = {
  id: string;
  name: string;
  address: string;
  type: EntryPointType;
  protocol?: Protocol;
  protocols?: Protocol[];
  tls?: TlsConfig;
  read_timeout_ms?: number;
  write_timeout_ms?: number;
  max_connections?: number;
  access_log_enabled?: boolean;
};

export type ListRoutesResponse = {
  routes: Route[];
  total_count: number;
  page: number;
  page_size: number;
};

export type ListServicesResponse = {
  services: Service[];
  total_count: number;
  page: number;
  page_size: number;
};

export type ListMiddlewaresResponse = {
  middlewares: Middleware[];
  total_count: number;
  page: number;
  page_size: number;
};

export type ListEntryPointsResponse = {
  entry_points: EntryPoint[];
  total_count: number;
  page: number;
  page_size: number;
};

export type ListTLSOptionsResponse = {
  tls_options: TLSOption[];
  total_count: number;
  page: number;
  page_size: number;
};

export type ListUsersResponse = {
  users: User[];
  total_count: number;
  page: number;
  page_size: number;
};
