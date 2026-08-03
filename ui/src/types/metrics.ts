export type GoldenSignals = {
  requestsTotal: number;
  errorsTotal: number;
  errorRate: number;
  avgLatencyMs: number;
  p50LatencyMs: number;
  p95LatencyMs: number;
  p99LatencyMs: number;
  inFlightTotal: number;
  bytesInTotal: number;
  bytesOutTotal: number;
  activeConnTotal: number;
  requestsToday: number;
  bytesToday: number;
};

export type RouteMetric = {
  route: string;
  service: string;
  requests: number;
  errors: number;
  errorRate: number;
  avgLatencyMs: number;
  inFlight: number;
  bytesIn: number;
  bytesOut: number;
  statusCodes: Record<string, number>;
  failures: LabeledCount[] | null;
};

export type LabeledCount = {
  label: string;
  value: number;
  subtext?: string;
};

export type MiddlewareMetrics = {
  rateLimitRejected: LabeledCount[] | null;
  wafBlocked: LabeledCount[] | null;
  fastPathBlocked: LabeledCount[] | null;
  cacheHits: number;
  cacheMisses: number;
  cacheHitRate: number;
  authFailures: LabeledCount[] | null;
  compressBytesIn: number;
  compressBytesOut: number;
  compressionRatio: number;
  turnstilePass: number;
  turnstileFail: number;
  geoipBlocked: LabeledCount[] | null;
  hmacFailures: number;
  retriesSuccess: number;
  retriesFailure: number;
  configReloads: number;
  cacheInvalidations: number;
  mitigatedThreats: LabeledCount[] | null;
  botMitigations: LabeledCount[] | null;
  ebpfDroppedPackets: LabeledCount[] | null;
};

export type TLSCertMetric = {
  domain: string;
  certName: string;
  expiryEpoch: number;
  daysRemaining: number;
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
  bytesIn: number;
  bytesOut: number;
};

export type CountryMetric = {
  country: string;
  countryName?: string;
  requests: number;
  bytesIn: number;
  bytesOut: number;
};

export type DomainMetric = {
  domain: string;
  requests: number;
  bytesIn: number;
  bytesOut: number;
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
  uptimeSeconds: number;
  goroutines: number;
  memoryAllocBytes: number;
  memoryTotalAllocBytes: number;
  memorySysBytes: number;
  cpuUsagePercent: number;
  memoryUsagePercent: number;
  cpuCores: number;
  memoryTotalGb: number;
  storageUsageGb: number;
  storageTotalGb: number;
  storageUsagePercent: number;
};

export type MetricsSnapshot = {
  goldenSignals: GoldenSignals;
  routeMetrics: RouteMetric[] | null;
  middleware: MiddlewareMetrics;
  tlsCertificates: TLSCertMetric[] | null;
  targets: TargetMetric[] | null;
  ipMetrics: IPMetric[] | null;
  countryMetrics: CountryMetric[] | null;
  protocolMetrics: LabeledCount[] | null;
  domainMetrics: DomainMetric[] | null;
  hourlyDomainMetrics: DomainStats[] | null;
  domainStatsRolling24h: DomainStats[] | null;
  trafficHistory: TrafficSample[] | null;
  activeSuspiciousSessions: number;
  activeUnverifiedClients: number;
  activeShunnedEntities: LabeledCount[] | null;
  activeAnomalyScoreAverage: number;
  system: SystemMetrics;
  security: SecurityInsights;
  mitigationFunnel?: MitigationFunnel;
};

export type MitigationFunnel = {
  httpIngress: number;
  wafBlocked: number;
  fastPathBlocked: number;
  rateLimited: number;
  geoipBlocked: number;
  authFailures: number;
  turnstileFailures: number;
  hmacFailures: number;
  botBlocked: number;
  fileSecurityBlocked: number;
  deceptionBlocked: number;
  advancedSecurityBlocked: number;
  totalMitigated: number;
  allowed: number;
  serverErrors: number;
  xdpPacketsDropped: number;
};

export type SecurityInsights = {
  topThreatSources: LabeledCount[] | null;
  topThreatTypes: LabeledCount[] | null;
  threatsByCountry: LabeledCount[] | null;
  attackTrend: TrafficSample[] | null;
  recentAnomalies: SecurityThreat[] | null;
  totalAnomalies: number;
  activeThreats: number;
  mitigatedToday: number;
  heavyHitters: HeavyHitter[] | null;
  globalThreatScore: number;
  ebpfTopIPs?: IPStat[] | null;
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
  sourceIp: string;
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
