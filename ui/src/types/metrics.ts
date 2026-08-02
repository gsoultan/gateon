export type GoldenSignals = {
  requests_total: number;
  errors_total: number;
  error_rate: number;
  avgLatencyMs: number;
  p50_latency_ms: number;
  p95_latency_ms: number;
  p99_latency_ms: number;
  in_flight_total: number;
  bytes_in_total: number;
  bytes_out_total: number;
  activeConnTotal: number;
  requests_today: number;
  bytes_today: number;
};

export type RouteMetric = {
  route: string;
  service: string;
  requests: number;
  errors: number;
  error_rate: number;
  avgLatencyMs: number;
  in_flight: number;
  bytes_in: number;
  bytes_out: number;
  statusCodes: Record<string, number>;
  failures: LabeledCount[] | null;
};

export type LabeledCount = {
  label: string;
  value: number;
  subtext?: string;
};

export type MiddlewareMetrics = {
  rate_limit_rejected: LabeledCount[] | null;
  waf_blocked: LabeledCount[] | null;
  fast_path_blocked: LabeledCount[] | null;
  cache_hits: number;
  cache_misses: number;
  cache_hit_rate: number;
  auth_failures: LabeledCount[] | null;
  compress_bytes_in: number;
  compress_bytes_out: number;
  compression_ratio: number;
  turnstile_pass: number;
  turnstile_fail: number;
  geoip_blocked: LabeledCount[] | null;
  hmac_failures: number;
  retries_success: number;
  retries_failure: number;
  config_reloads: number;
  cache_invalidations: number;
  mitigated_threats: LabeledCount[] | null;
  bot_mitigations: LabeledCount[] | null;
  ebpf_dropped_packets: LabeledCount[] | null;
};

export type TLSCertMetric = {
  domain: string;
  cert_name: string;
  expiry_epoch: number;
  days_remaining: number;
};

export type TargetMetric = {
  route: string;
  target: string;
  healthy: boolean;
  activeConn: number;
};

export type IPMetric = {
  ip: string;
  requests: number;
  bytes_in: number;
  bytes_out: number;
};

export type CountryMetric = {
  country: string;
  countryName?: string;
  requests: number;
  bytes_in: number;
  bytes_out: number;
};

export type DomainMetric = {
  domain: string;
  requests: number;
  bytes_in: number;
  bytes_out: number;
};

export type DomainStats = {
  domain: string;
  hour?: number;
  requestCount: number;
  bytesTotal: number;
  latencySumSeconds: number;
  avgLatencySeconds: number;
};

export type SystemMetrics = {
  uptime_seconds: number;
  goroutines: number;
  memory_alloc_bytes: number;
  memory_total_alloc_bytes: number;
  memory_sys_bytes: number;
  cpu_usage_percent: number;
  memoryUsagePercent: number;
  cpuCores: number;
  memoryTotalGb: number;
  storageUsageGb: number;
  storageTotalGb: number;
  storageUsagePercent: number;
};

export type MetricsSnapshot = {
  golden_signals: GoldenSignals;
  route_metrics: RouteMetric[] | null;
  middleware: MiddlewareMetrics;
  tls_certificates: TLSCertMetric[] | null;
  targets: TargetMetric[] | null;
  ip_metrics: IPMetric[] | null;
  country_metrics: CountryMetric[] | null;
  protocol_metrics: LabeledCount[] | null;
  domain_metrics: DomainMetric[] | null;
  hourly_domain_metrics: DomainStats[] | null;
  domain_stats_rolling24h: DomainStats[] | null;
  traffic_history: TrafficSample[] | null;
  activeSuspiciousSessions: number;
  activeUnverifiedClients: number;
  activeShunnedEntities: LabeledCount[] | null;
  activeAnomalyScoreAverage: number;
  system: SystemMetrics;
  security: SecurityInsights;
  mitigation_funnel?: MitigationFunnel;
};

export type MitigationFunnel = {
  http_ingress: number;
  waf_blocked: number;
  fast_path_blocked: number;
  rate_limited: number;
  geoip_blocked: number;
  auth_failures: number;
  turnstile_failures: number;
  hmac_failures: number;
  bot_blocked: number;
  file_security_blocked: number;
  deception_blocked: number;
  advancedSecurityBlocked: number;
  totalMitigated: number;
  allowed: number;
  server_errors: number;
  xdp_packets_dropped: number;
};

export type SecurityInsights = {
  top_threat_sources: LabeledCount[] | null;
  top_threat_types: LabeledCount[] | null;
  threats_by_country: LabeledCount[] | null;
  attack_trend: TrafficSample[] | null;
  recent_anomalies: SecurityThreat[] | null;
  total_anomalies: number;
  activeThreats: number;
  mitigated_today: number;
  heavy_hitters: HeavyHitter[] | null;
  global_threat_score: number;
  ebpf_top_ips?: IPStat[] | null;
};

export type IPStat = {
  ip: string;
  count: number;
};

export type HeavyHitter = {
  network: string;
  count: number;
  percentage: number;
};

export type SecurityThreat = {
  id: string;
  type: string;
  source_ip: string;
  fingerprint: string;
  score: number;
  details: string;
  timestamp: string;
  ja3: string;
  ja4: string;
  routeId: string;
  requestUri: string;
  category: string;
  severity: string;
  asn: string;
  actionTaken: string;
  countryCode: string;
  mitigated: boolean;
  requestHeaders?: string;
  requestBody?: string;
  responseHeaders?: string;
  responseBody?: string;
  userAgent?: string;
  httpMethod?: string;
  recommendation?: string;
  confidence?: number;
  entropy?: number;
  clusterSize?: number;
};

export type TrafficSample = {
  ts: number;
  requests: number;
  bytes: number;
};

export type DonutChartDataItem = {
  name: string;
  value: number;
  color: string;
};
