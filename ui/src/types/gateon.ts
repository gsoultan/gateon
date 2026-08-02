export type WafRule = {
  id: string;
  name: string;
  directive: string;
  enabled: boolean;
  paranoiaLevel: number;
  category: string;
  createdAt: string;
  updatedAt: string;
};

export type ListWafRulesResponse = {
  rules: WafRule[];
  total: number;
};

export type ListWafRulesRequest = {
  limit?: number;
  offset?: number;
  search?: string;
  category?: string;
};

export type CreateWafRuleRequest = {
  rule: Partial<WafRule>;
};

export type UpdateWafRuleRequest = {
  rule: WafRule;
};

export type DeleteWafRuleRequest = {
  id: string;
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
  requestCount: number;
  bytesTotal: number;
  latencySumSeconds: number;
  avgLatencySeconds: number;
};

export type TargetStats = {
  url: string;
  alive: boolean;
  requestCount: number;
  errorCount: number;
  avgLatencyMs: number;
  activeConn: number;
  circuitState?: string;
  statusCodes?: Record<string, number>;
};

export type Target = {
  url: string;
  weight: number;
  /** For HTTP: "http" | "https"; for gRPC: "h2" | "h2c" */
  protocol?: string;
  proxyProtocolEnabled?: boolean;
  proxyProtocolVersion?: ProxyProtocolVersion;
};

export enum ProxyProtocolVersion {
  PROXY_PROTOCOL_VERSION_UNSPECIFIED = 0,
  PROXY_PROTOCOL_VERSION_V1 = 1,
  PROXY_PROTOCOL_VERSION_V2 = 2,
}

export enum TlsClientCertSelectionStrategy {
  TLS_CLIENT_CERT_SELECTION_STRATEGY_STATIC = 0,
  TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HOST = 1,
  TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HEADER = 2,
}

export type TlsClientIdentity = {
  id?: string;
  certFile?: string;
  keyFile?: string;
  matchHosts?: string[];
  matchHeader?: string;
  matchHeaderValue?: string;
};

export type TlsClientConfig = {
  enabled: boolean;
  certFile?: string;
  keyFile?: string;
  caFile?: string;
  skipVerify?: boolean;
  serverName?: string;
  certSelectionStrategy?: TlsClientCertSelectionStrategy;
  certIdentities?: TlsClientIdentity[];
};

export type Service = {
  id: string;
  name: string;
  weightedTargets: Target[];
  loadBalancerPolicy: string;
  healthCheckPath: string;
  backendType?: "http" | "grpc" | "graphql" | "tcp" | "udp";
  l4HealthCheckIntervalMs?: number;
  l4HealthCheckTimeoutMs?: number;
  l4UdpSessionTimeoutS?: number;
  l4ProxyProtocol?: boolean;
  discoveryUrl?: string;
  tlsClientConfig?: TlsClientConfig;
  /** Overrides the target port for health checks (e.g. HTTP health on port 3001 while gRPC runs on 3000). */
  healthCheckPort?: number;
  /** Overrides the scheme for health checks (e.g. "http", "https"). */
  healthCheckProtocol?: string;
  /** Determines whether to use HTTP or gRPC standard health check. */
  healthCheckType?: HealthCheckType;
};

export enum HealthCheckType {
  HEALTH_CHECK_TYPE_UNSPECIFIED = 0,
  HEALTH_CHECK_TYPE_HTTP = 1,
  HEALTH_CHECK_TYPE_GRPC = 2,
  HEALTH_CHECK_TYPE_TCP = 3,
  HEALTH_CHECK_TYPE_CUSTOM = 4,
}

export type RouteTLSConfig = {
  certificateIds: string[];
  optionId?: string;
};

export type TLSOption = {
  id: string;
  name: string;
  minTlsVersion?: string;
  maxTlsVersion?: string;
  cipherSuites?: string[];
  prefer_server_cipher_suites?: boolean;
  clientAuthType?: string;
  sniStrict?: boolean;
  alpnProtocols?: string[];
  clientAuthorityIds?: string[];
};

export type Route = {
  id: string;
  name?: string;
  type: "http" | "grpc" | "graphql" | "tcp" | "udp";
  entryPoints: string[];
  rule: string;
  priority: number;
  middlewares: string[];
  serviceId: string;
  tls?: RouteTLSConfig;
  disabled?: boolean;
};

export type StatusResponse = {
  status: string;
  version: string;
  uptime: number;
  memoryUsage: number;
  cpuUsage: number;
  memoryUsagePercent: number;
  routesCount: number;
  servicesCount: number;
  entryPointsCount: number;
  middlewaresCount: number;
  cpuCores?: number;
  memoryTotalGb?: number;
  storageUsageGb?: number;
  storageTotalGb?: number;
  storageUsagePercent?: number;
  clamavInstalled?: boolean;
  profile?: string;
  profilePinned?: boolean;
};

export type CertificateValidation = {
  valid: boolean;
  warnings?: string[];
  recommendedCiphers?: string[];
};

export type Certificate = {
  id: string;
  name: string;
  certFile: string;
  keyFile: string;
  /** Optional CA/intermediate certificate file appended to the served chain during SNI selection. */
  caFile?: string;
  host?: string;
  validation?: CertificateValidation;
};

export type ClientAuthority = {
  id: string;
  name: string;
  caFile: string;
  /** Optional per-CA preferred client auth mode; UI hint, may be enforced by server config */
  clientAuthType?: string;
};

export type AcmeConfig = {
  enabled: boolean;
  email?: string;
  ca_server?: string;
  challenge_type?: string;
  dnsProvider?: string;
  dnsConfig?: Record<string, string>;
};

export type TlsConfig = {
  enabled: boolean;
  email?: string;
  domains?: string[];
  autoRedirect?: boolean;
  minTlsVersion?: string;
  maxTlsVersion?: string;
  clientAuthType?: string;
  cipherSuites?: string[];
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
  serviceName?: string;
};

export type LogConfig = {
  level?: "debug" | "info" | "warn" | "error";
  development?: boolean;
  format?: "json" | "text";
  pathStatsRetentionDays?: number;
  accessLogRetentionDays?: number;
  securityThreatRetentionDays?: number;
  audit_log_retention_days?: number;
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
  two_factor_enabled?: boolean;
  two_factor_secret?: string;
  recovery_codes?: string[];
  disabled?: boolean;
  two_factor_pending?: boolean;
};

export type LoginResponse = {
  token: string;
  user: User;
  two_factor_required?: boolean;
  two_factor_setup_required?: boolean;
};

export type Setup2FARequest = {
  id: string;
};

export type Setup2FAResponse = {
  secret: string;
  qr_code_url: string;
  recovery_codes: string[];
};

export type Verify2FARequest = {
  id: string;
  code: string;
};

export type Verify2FAResponse = {
  success: boolean;
  token?: string;
  user?: User;
};

export type IsSetupRequiredResponse = {
  required: boolean;
};

export type SetupRequest = {
  adminUsername: string;
  adminPassword: string;
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
  paranoiaLevel: number;
  custom_directives?: string;
  sqli?: boolean;
  xss?: boolean;
  lfi?: boolean;
  rce?: boolean;
  php?: boolean;
  scanner?: boolean;
  protocol?: boolean;
  java?: boolean;
  nodejs?: boolean;
  wordpress?: boolean;
  ipReputation?: boolean;
  dosProtection?: boolean;
  malwareDetection?: boolean;
  ransomwareDetection?: boolean;
  dlp?: boolean;
  anomalyThreshold?: number;
  bot_management?: BotManagementConfig;
  requestBody_limit?: number;
  responseBody_limit?: number;
  auditLogPath?: string;
  auditLogRelevantOnly?: boolean;
  allowed_admin_ips?: string[];
  auto_update_rules?: boolean;
  update_interval_hours?: number;
  rules_url?: string;
  clamavAddr?: string;
  clamav?: ClamavConfig;
  entropy_threshold?: number;
  disable_entropy?: boolean;
  trustCloudflareHeaders?: boolean;
};

export type ClamavConfig = {
  installation_mode?: ClamavInstallationMode;
  auto_install?: boolean;
  docker_image?: string;
  full_scan_schedule?: string;
  low_resource_mode?: boolean;
  clamavAddr?: string;
};

export enum ClamavInstallationMode {
  INSTALLATION_MODE_UNSPECIFIED = 0,
  INSTALLATION_MODE_LOCAL = 1,
  INSTALLATION_MODE_DOCKER = 2,
}

export type BotManagementConfig = {
  enabled?: boolean;
  enable_js_challenge?: boolean;
  enable_browser_integrity?: boolean;
  challenge_timeout_seconds?: number;
  secret_key?: string;
};

export type HaConfig = {
  enabled?: boolean;
  interface?: string;
  virtual_router_id?: number;
  priority?: number;
  virtual_ips?: string[];
  advert_int?: number;
  auth_pass?: string;
  enable_gossip?: boolean;
  gossip_bind_addr?: string;
  gossip_bind_port?: number;
  gossip_peers?: string[];
};

export type AnomalyDetectionConfig = {
  enabled?: boolean;
  prometheus_url?: string;
  check_interval_seconds?: number;
  sensitivity?: number;
  security_threat_threshold?: number;
  anomaly_retention_days?: number;
  enable_behavioral_fingerprinting?: boolean;
  enable_brute_force_detection?: boolean;
  enable_exploit_detection?: boolean;
};

export type EbpfConfig = {
  enabled?: boolean;
  xdp_rate_limit?: boolean;
  tc_filtering?: boolean;
  interface?: string;
  xdp_ip_shunning?: boolean;
  xdp_load_balancing?: boolean;
  enable_knocking?: boolean;
  mgmt_port?: number;
  knocking_sequence?: number[];
  xdp_cuckoo_filter?: boolean;
  af_xdp_phantom?: boolean;
  xdp_ja4_blocklist?: boolean;
};

export interface GeoIPConfig {
  enabled?: boolean;
  db_path?: string;
  asn_db_path?: string;
  country_db_path?: string;
  maxmind_license_key?: string;
  auto_update?: boolean;
  update_interval_days?: number;
  blocked_countries?: string[];
  allowed_countries?: string[];
  xdp_geofencing?: boolean;
}

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
  geoip?: GeoIPConfig;
  security_advanced?: SecurityAdvancedConfig;
  alerting?: AlertingConfig;
  audit?: AuditConfig;
  profile?: string;
  titan?: TitanConfig;
};

export type TitanConfig = {
  enabled: boolean;
  enable_phantom: boolean;
  enable_ai_predictor: boolean;
  enable_pqc: boolean;
  enable_governor: boolean;
  aiModelPath: string;
};

export type AlertingConfig = {
  enabled: boolean;
  dispatchers: AlertDispatcher[];
  playbooks: AlertPlaybook[];
};

export type AlertDispatcher = {
  id: string;
  name: string;
  type: string;
  webhook_url?: string;
  slack_channel?: string;
  telegram_bot_token?: string;
  telegram_chat_id?: string;
};

export type AlertPlaybook = {
  id: string;
  name: string;
  event_type: string;
  threshold: number;
  dispatcher_ids: string[];
  action: string;
};

export type AuditConfig = {
  enabled: boolean;
  sign_entries: boolean;
  signature_key?: string;
  retention_days?: number;
  archive_on_retention?: boolean;
};

export type SecurityAdvancedConfig = {
  deception?: DeceptionConfig;
  tarpit?: TarpitConfig;
  entropy?: EntropyConfig;
  behavioral?: BehavioralConfig;
  pow?: PowConfig;
  ipReputation?: IPReputationConfig;
  tls_binding?: TlsBindingConfig;
};

export type TlsBindingConfig = {
  enabled: boolean;
  cookie_name?: string;
};

export type IPReputationConfig = {
  enabled?: boolean;
  feed_urls?: string[];
  update_interval_hours?: number;
  block_threshold?: number;
  integrations?: IPReputationIntegration[];
};

export type IPReputationIntegration = {
  id: string;
  name: string;
  type: string; // "abuseipdb", "virustotal", etc.
  api_key: string;
  enabled: boolean;
  confidence_threshold?: number;
};

export type DeceptionConfig = {
  enabled: boolean;
  honeypot_paths: string[];
  inject_invisible_links: boolean;
  invisible_link_paths: string[];
  honey_forms?: string[];
  canary_header?: string;
  canary_token?: string;
  enable_troll_response?: boolean;
};

export type TarpitConfig = {
  enabled: boolean;
  delay_base_ms: number;
  delay_max_ms: number;
  score_threshold: number;
};

export type EntropyConfig = {
  enabled: boolean;
  threshold: number;
};

export type BehavioralConfig = {
  enabled: boolean;
  enable_impossible_travel: boolean;
  enable_sequence_validation: boolean;
};

export type PowConfig = {
  enabled: boolean;
  difficulty: number;
  score_threshold: number;
};

export type ManagementConfig = {
  bind?: string;
  port?: string;
  allowed_ips?: string[];
  allow_public_management?: boolean;
  allowed_hosts?: string[];
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
  readTimeoutMs?: number;
  writeTimeoutMs?: number;
  max_connections?: number;
  accessLogEnabled?: boolean;
};

export type ListRoutesResponse = {
  routes: Route[];
  totalCount: number;
  page: number;
  page_size: number;
};

export type ListServicesResponse = {
  services: Service[];
  totalCount: number;
  page: number;
  page_size: number;
};

export type ListMiddlewaresResponse = {
  middlewares: Middleware[];
  totalCount: number;
  page: number;
  page_size: number;
};

export type ListEntryPointsResponse = {
  entry_points: EntryPoint[];
  totalCount: number;
  page: number;
  page_size: number;
};

export type ListTLSOptionsResponse = {
  tls_options: TLSOption[];
  totalCount: number;
  page: number;
  page_size: number;
};

export type ListUsersResponse = {
  users: User[];
  totalCount: number;
  page: number;
  page_size: number;
};

export type CertificateStatus = {
  domain: string;
  expiry: string;
  valid: boolean;
  error: string;
  issuer: string;
};

export type MiddlewareDiagnostic = {
  id: string;
  name: string;
  type: string;
  healthy: boolean;
  error: string;
};

export type RouteDiagnostic = {
  id: string;
  name: string;
  rule: string;
  serviceId: string;
  serviceName: string;
  serviceHealthy: boolean;
  middlewares: MiddlewareDiagnostic[];
  healthy: boolean;
  error: string;
};

export type EntryPointDiagnostic = {
  id: string;
  address: string;
  type: string;
  listening: boolean;
  totalConnections: number;
  activeConnections: number;
  lastError: string;
  name: string;
  certificates?: CertificateStatus[];
  routes?: RouteDiagnostic[];
};

export type HandshakeError = {
  timestamp: string;
  remoteAddr: string;
  error: string;
  entrypointId: string;
  entrypointName: string;
};

export type GossipStatus = {
  enabled: boolean;
  members_count: number;
  member_names: string[];
  messagesSent: number;
  messagesReceived: number;
};

export type SystemInfo = {
  publicIp: string;
  cloudflareReachable: boolean;
  uptime: string;
  goroutines: number;
  memoryUsage: string;
  cpuUsage: string;
  version: string;
  gossip?: GossipStatus;
  ebpf?: EbpfStats;
  titan?: TitanStats;
};

export type TitanStats = {
  phantomEnabled: boolean;
  phantomEngine: string;
  activePhantomPorts: number;
  aiPredictorEnabled: boolean;
  aiModelStatus: string;
  cuckooFilterEntries: number;
  pqcEnabled: boolean;
  governor?: ResourceGovernorStats;
};

export type ResourceGovernorStats = {
  active: boolean;
  memoryHooksCount: number;
  cpuHooksCount: number;
  memoryPressurePercent: number;
  cpuPressurePercent: number;
};

export type EbpfStats = {
  enabled: boolean;
  shunnedIpsCount: number;
  droppedPackets: Record<string, number>;
};

export type Anomaly = {
  id?: string;
  type: string;
  severity: string;
  description: string;
  timestamp: string;
  source: string;
  recommendation: string;
  latitude?: number;
  longitude?: number;
  countryCode?: string;
  countryName?: string;
  ja4?: string;
  ja4plus?: string;
  ja3?: string;
  ja4h?: string;
  score?: number;
  routeId?: string;
  requestUri?: string;
  mitigated?: boolean;
  category?: string;
  actionTaken?: string;
  requestHeaders?: string;
  requestBody?: string;
  responseHeaders?: string;
  responseBody?: string;
  userAgent?: string;
  httpMethod?: string;
  confidence?: number;
  entropy?: number;
  clusterSize?: number;
  triggeredRules?: string;
  reputation?: number;
  sourceIps?: string[];
};

export type Reputation = {
  fingerprint: string;
  score: number;
  lastEvent: string;
  violationCount: number;
  history: string[];
};

export type DependencyHealth = {
  name: string;
  healthy: boolean;
  error: string;
  latencyMs: string;
};

export type GetDiagnosticsResponse = {
  entryPoints: EntryPointDiagnostic[];
  recentTlsErrors: HandshakeError[];
  system: SystemInfo;
  anomalies: Anomaly[];
  dependencies: DependencyHealth[];
  totalMitigations: number;
};

export type GetCloudflareIPsResponse = {
  ipv4_cidrs: string[];
  ipv6_cidrs: string[];
};

export type TraceHop = {
  hop: number;
  ip: string;
  latitude: number;
  longitude: number;
  countryCode: string;
  city: string;
  rtt_ms: number;
};

export type TraceRouteResponse = {
  hops: TraceHop[];
};

export type ValidateCORSRequest = {
  url: string;
  origin: string;
  method: string;
  headers: Record<string, string>;
  authBearerToken: string;
};

export type ValidateCORSResponse = {
  isAllowed: boolean;
  message: string;
  responseHeaders: Record<string, string>;
  checks: string[];
  isPreflight: boolean;
  middlewareConfig: Record<string, string>;
  routeName: string;
  suggestions: string[];
  routeId: string;
};

export type RemoveMitigatedThreatRequest = {
  source: string;
  ja4plus?: string;
  ja4h?: string;
};

export type RemoveMitigatedThreatResponse = {
  success: boolean;
  message: string;
};

export type MitigateThreatRequest = {
  source: string;
  type?: string;
  reason?: string;
  category?: string;
};

export type MitigateThreatResponse = {
  success: boolean;
  message: string;
};

export type InstallClamavRequest = {
  mode: ClamavInstallationMode;
  sudo_password?: string;
};

export type InstallClamavResponse = {
  success: boolean;
  message: string;
};

export type UninstallClamavRequest = {};

export type UninstallClamavResponse = {
  success: boolean;
  message: string;
};

export type RunDeepScanRequest = {};

export type RunDeepScanResponse = {
  success: boolean;
  message: string;
  status?: DeepScanStatus;
};

export type DeepScanStatus = {
  isRunning: boolean;
  lastScan: string;
  lastError: string;
  lastResult: string;
};

export type AuditLog = {
  id: string;
  userId: string;
  action: string;
  resource: string;
  details: string;
  timestamp: string;
  ipAddress: string;
  signature: string;
};

export type AuditArchive = {
  filename: string;
  size: number;
  created_at: string;
};

export type ListAuditArchivesResponse = {
  archives: AuditArchive[];
};

export type GetAuditArchiveResponse = {
  logs: AuditLog[];
};

export type LimitStats = {
  rate_limit_rejected: Record<string, number>;
  inflight_rejected: Record<string, number>;
  buffering_rejected: Record<string, number>;
};

export type AggStats = {
  totalRequests: number;
  totalBandwidthBytes: number;
  totalErrors: number;
  activeConnections: number;
  openCircuits: number;
  halfOpenCircuits: number;
  healthyTargets: number;
  totalTargets: number;
  cpuUsage: number;
  memoryUsage: number;
};

export type RequestDeltaSample = {
  ts: number;
  requests: number;
};

export type CountryTraffic = {
  country: string;
  name?: string;
  requestCount: number;
};
