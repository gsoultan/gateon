// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { MetricsSnapshot } from './metrics';

export type { MetricsSnapshot };

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
  pageSize?: number;
  page?: number;
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
  preferServerCipherSuites?: boolean;
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
  // Unified fields
  uptimeSeconds?: number;
  memoryUsageMb?: number;
  memoryTotalMb?: number;
  publicIp?: string;
  titanEnabled?: boolean;
  neuralSentinelEnabled?: boolean;
  graphIntelligenceEnabled?: boolean;
  predictiveAiEnabled?: boolean;
  pqcEnabled?: boolean;
  tpmEnabled?: boolean;
  resourceGovernorEnabled?: boolean;
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
  caServer?: string;
  challengeType?: string;
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
  clientAuthorities?: ClientAuthority[];
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
  auditLogRetentionDays?: number;
};

export type TransportConfig = {
  maxIdleConns?: number;
  maxIdleConnsPerHost?: number;
  idleConnTimeoutSeconds?: number;
};

export type DatabaseConfig = {
  driver?: "sqlite" | "postgres" | "mysql" | "mariadb";
  sqlitePath?: string;
  host?: string;
  port?: number;
  user?: string;
  password?: string;
  database?: string;
  sslMode?: string;
};

export type AuthConfig = {
  enabled?: boolean;
  pasetoSecret?: string;
  /** @deprecated Use databaseConfig or databaseUrl. */
  sqlitePath?: string;
  /** Fallback connection string (encrypted when GATEON_ENCRYPTION_KEY is set) */
  databaseUrl?: string;
  databaseConfig?: DatabaseConfig;
};

export type User = {
  id: string;
  username: string;
  password?: string;
  role: "admin" | "operator" | "viewer";
  twoFactorEnabled?: boolean;
  twoFactorSecret?: string;
  recoveryCodes?: string[];
  disabled?: boolean;
  twoFactorPending?: boolean;
};

export type LoginResponse = {
  token: string;
  user: User;
  twoFactorRequired?: boolean;
  twoFactorSetupRequired?: boolean;
};

export type Setup2FARequest = {
  id: string;
};

export type Setup2FAResponse = {
  secret: string;
  qrCodeUrl: string;
  recoveryCodes: string[];
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
  pasetoSecret: string;
  managementBind: string;
  managementPort: string;
  // Optional for first-run wizard database selection
  databaseUrl?: string;
  databaseConfig?: DatabaseConfig;
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
  wasmBlob?: string; // base64 encoded
};

export type WafConfig = {
  enabled: boolean;
  useCrs: boolean;
  paranoiaLevel: number;
  customDirectives?: string;
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
  /**
   * What to do when a data-leak rule fires: "block" (the default) refuses the
   * response, "redact" removes the finding and forwards the rest, "audit"
   * records it and forwards untouched. Anything else, including empty, blocks.
   * Mirrors WafConfig.dlp_action in proto/gateon/v1/global.proto.
   */
  dlpAction?: string;
  anomalyThreshold?: number;
  botManagement?: BotManagementConfig;
  requestBodyLimit?: number;
  responseBodyLimit?: number;
  auditLogPath?: string;
  auditLogRelevantOnly?: boolean;
  allowedAdminIps?: string[];
  autoUpdateRules?: boolean;
  clamavAddr?: string;
  clamav?: ClamavConfig;
  entropyThreshold?: number;
  disableEntropy?: boolean;
  trustCloudflareHeaders?: boolean;
  appProfiles?: string[];
  ssrfProtection?: boolean;
  origins?: string[];
};

/**
 * Platform exception profiles the engine ships.
 *
 * These are a closed set compiled into the gateway, not something the API
 * discovers, so they are listed here rather than fetched — the values must match
 * `AppProfile` in internal/security/waf/appprofile.go. A name the backend does
 * not recognise is logged there and loads nothing, which is why this list is the
 * only place the dashboard offers.
 *
 * A profile is not a compatibility mode and does not disable a rule. Each entry
 * suppresses a named rule on a named path and field, because the platform's
 * ordinary traffic is a superset of an attack shape there.
 */
export const WAF_APP_PROFILES = [
  { value: "wordpress", label: "WordPress" },
  { value: "drupal", label: "Drupal" },
  { value: "laravel", label: "Laravel" },
  { value: "issue_tracker", label: "Issue tracker (Jira, GitLab)" },
] as const;

export type ClamavConfig = {
  installationMode?: ClamavInstallationMode;
  autoInstall?: boolean;
  dockerImage?: string;
  fullScanSchedule?: string;
  lowResourceMode?: boolean;
  clamavAddr?: string;
};

export enum ClamavInstallationMode {
  INSTALLATION_MODE_UNSPECIFIED = 0,
  INSTALLATION_MODE_LOCAL = 1,
  INSTALLATION_MODE_DOCKER = 2,
}

export type BotManagementConfig = {
  enabled?: boolean;
  enableJsChallenge?: boolean;
  enableBrowserIntegrity?: boolean;
  challengeTimeoutSeconds?: number;
  secretKey?: string;
};

export type HaConfig = {
  enabled?: boolean;
  interface?: string;
  virtualRouterId?: number;
  priority?: number;
  virtualIps?: string[];
  advertInt?: number;
  authPass?: string;
  enableGossip?: boolean;
  gossipBindAddr?: string;
  gossipBindPort?: number;
  gossipPeers?: string[];
};

export type AnomalyDetectionConfig = {
  enabled?: boolean;
  prometheusUrl?: string;
  checkIntervalSeconds?: number;
  sensitivity?: number;
  securityThreatThreshold?: number;
  anomalyRetentionDays?: number;
  enableBehavioralFingerprinting?: boolean;
  enableBruteForceDetection?: boolean;
  enableExploitDetection?: boolean;
};

export type EbpfConfig = {
  enabled?: boolean;
  xdpRateLimit?: boolean;
  tcFiltering?: boolean;
  interface?: string;
  xdpIpShunning?: boolean;
  xdpLoadBalancing?: boolean;
  enableKnocking?: boolean;
  mgmtPort?: number;
  knockingSequence?: number[];
  xdpCuckooFilter?: boolean;
  afXdpPhantom?: boolean;
  xdpJa4Blocklist?: boolean;
};

export interface GeoIPConfig {
  enabled?: boolean;
  dbPath?: string;
  asnDbPath?: string;
  countryDbPath?: string;
  maxmindLicenseKey?: string;
  autoUpdate?: boolean;
  updateIntervalDays?: number;
  blockedCountries?: string[];
  allowedCountries?: string[];
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
  anomalyDetection?: AnomalyDetectionConfig;
  ebpf?: EbpfConfig;
  management?: ManagementConfig;
  geoip?: GeoIPConfig;
  securityAdvanced?: SecurityAdvancedConfig;
  alerting?: AlertingConfig;
  audit?: AuditConfig;
  profile?: string;
  titan?: TitanConfig;
};

export type TitanConfig = {
  enabled: boolean;
  enablePhantom: boolean;
  enableAiPredictor: boolean;
  enablePqc: boolean;
  enableGovernor: boolean;
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
  webhookUrl?: string;
  slackChannel?: string;
  telegramBotToken?: string;
  telegramChatId?: string;
};

export type AlertPlaybook = {
  id: string;
  name: string;
  eventType: string;
  threshold: number;
  dispatcherIds: string[];
  action: string;
};

export type AuditConfig = {
  enabled: boolean;
  signEntries: boolean;
  signatureKey?: string;
  retentionDays?: number;
  archiveOnRetention?: boolean;
};

export type SecurityAdvancedConfig = {
  deception?: DeceptionConfig;
  tarpit?: TarpitConfig;
  entropy?: EntropyConfig;
  behavioral?: BehavioralConfig;
  pow?: PowConfig;
  ipReputation?: IPReputationConfig;
  tlsBinding?: TlsBindingConfig;
};

export type TlsBindingConfig = {
  enabled: boolean;
  cookieName?: string;
};

export type IPReputationConfig = {
  enabled?: boolean;
  feedUrls?: string[];
  updateIntervalHours?: number;
  blockThreshold?: number;
  integrations?: IPReputationIntegration[];
};

export type IPReputationIntegration = {
  id: string;
  name: string;
  type: string; // "abuseipdb", "virustotal", etc.
  apiKey: string;
  enabled: boolean;
  confidenceThreshold?: number;
};

export type DeceptionConfig = {
  enabled: boolean;
  honeypotPaths: string[];
  injectInvisibleLinks: boolean;
  invisibleLinkPaths: string[];
  honeyForms?: string[];
  canaryHeader?: string;
  canaryToken?: string;
  enableTrollResponse?: boolean;
};

export type TarpitConfig = {
  enabled: boolean;
  delayBaseMs: number;
  delayMaxMs: number;
  scoreThreshold: number;
};

export type EntropyConfig = {
  enabled: boolean;
  threshold: number;
};

export type BehavioralConfig = {
  enabled: boolean;
  enableImpossibleTravel: boolean;
  enableSequenceValidation: boolean;
};

export type PowConfig = {
  enabled: boolean;
  difficulty: number;
  scoreThreshold: number;
};

export type ManagementConfig = {
  bind?: string;
  port?: string;
  allowedIps?: string[];
  allowPublicManagement?: boolean;
  allowedHosts?: string[];
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
  maxConnections?: number;
  accessLogEnabled?: boolean;
};

export type ListRoutesResponse = {
  routes: Route[];
  totalCount: number;
  page: number;
  pageSize: number;
};

export type ListServicesResponse = {
  services: Service[];
  totalCount: number;
  page: number;
  pageSize: number;
};

export type ListMiddlewaresResponse = {
  middlewares: Middleware[];
  totalCount: number;
  page: number;
  pageSize: number;
};

export type ListEntryPointsResponse = {
  entryPoints: EntryPoint[];
  totalCount: number;
  page: number;
  pageSize: number;
};

export type ListTLSOptionsResponse = {
  tlsOptions: TLSOption[];
  totalCount: number;
  page: number;
  pageSize: number;
};

export type ListUsersResponse = {
  users: User[];
  totalCount: number;
  page: number;
  pageSize: number;
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

// The connection and message counters are int64 in the proto, so
// protobuf-es v2 hands them back as bigint. React will not render one;
// call sites use String().
export type EntryPointDiagnostic = {
  id: string;
  address: string;
  type: string;
  listening: boolean;
  totalConnections: bigint;
  activeConnections: bigint;
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
  membersCount: number;
  memberNames: string[];
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
  // "entrypoints", one word, because that is the proto field name and
  // protojson emits it verbatim — it has no underscore to camel-case. The type
  // said entryPoints, so every read of it was undefined and the Diagnostics
  // page rendered "No entryPoints configured" while the gateway was returning
  // four. Verified against the wire, not inferred.
  entrypoints: EntryPointDiagnostic[];
  recentTlsErrors: HandshakeError[];
  system: SystemInfo;
  anomalies: Anomaly[];
  dependencies: DependencyHealth[];
  totalMitigations: number;
};

export type GetCloudflareIPsResponse = {
  ipv4Cidrs: string[];
  ipv6Cidrs: string[];
};

export type TraceHop = {
  hop: number;
  ip: string;
  latitude: number;
  longitude: number;
  countryCode: string;
  city: string;
  // int64 in the proto, so protobuf-es v2 surfaces it as bigint. React will
  // not render one, hence String() at the call site.
  rttMs: bigint;
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
  sudoPassword?: string;
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
  createdAt: string;
};

export type ListAuditArchivesResponse = {
  archives: AuditArchive[];
};

export type GetAuditArchiveResponse = {
  logs: AuditLog[];
};

export type LimitStats = {
  rateLimitRejected: Record<string, number>;
  inflightRejected: Record<string, number>;
  bufferingRejected: Record<string, number>;
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
