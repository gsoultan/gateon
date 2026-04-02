export type GoldenSignals = {
  requests_total: number;
  errors_total: number;
  error_rate: number;
  avg_latency_ms: number;
  p50_latency_ms: number;
  p95_latency_ms: number;
  p99_latency_ms: number;
  in_flight_total: number;
  bytes_in_total: number;
  bytes_out_total: number;
  active_conn_total: number;
};

export type RouteMetric = {
  route: string;
  service: string;
  requests: number;
  errors: number;
  error_rate: number;
  avg_latency_ms: number;
  in_flight: number;
  bytes_in: number;
  bytes_out: number;
  status_codes: Record<string, number>;
};

export type LabeledCount = {
  label: string;
  value: number;
};

export type MiddlewareMetrics = {
  rate_limit_rejected: LabeledCount[] | null;
  waf_blocked: LabeledCount[] | null;
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
  active_conn: number;
};

export type SystemMetrics = {
  uptime_seconds: number;
  goroutines: number;
  memory_alloc_bytes: number;
  memory_total_alloc_bytes: number;
  memory_sys_bytes: number;
};

export type MetricsSnapshot = {
  golden_signals: GoldenSignals;
  route_metrics: RouteMetric[] | null;
  middleware: MiddlewareMetrics;
  tls_certificates: TLSCertMetric[] | null;
  targets: TargetMetric[] | null;
  system: SystemMetrics;
};
