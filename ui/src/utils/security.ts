// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

export function getThreatColor(type: string, category?: string) {
  const t = (type || '').toLowerCase();
  const cat = (category || '').toLowerCase();
  
  if (t.includes('waf') || t.includes('sqli') || t.includes('xss') || cat === 'injection') return 'red.7';
  if (t.includes('bot') || t.includes('scanner') || cat === 'scanner') return 'orange.7';
  if (t.includes('geoip')) return 'blue.7';
  if (t.includes('ddos') || t.includes('flood') || cat === 'dos') return 'grape.7';
  if (t.includes('brute')) return 'yellow.7';
  if (cat === 'malware' || t.includes('ransomware')) return 'pink.7';
  if (cat === 'dlp' || t.includes('leak')) return 'cyan.7';
  return 'teal.7';
}

/**
 * A fingerprint block is a client build on one network, listed as
 * "<build>|<network>" (ADR 0026): the /24 as its first three octets, an IPv6
 * /64 as a prefix. splitScopedBlock names both halves, the /24 written as one,
 * so a confirmation can say exactly whom a release re-admits; null for any
 * other source.
 */
export function splitScopedBlock(source: string | undefined): { build: string; network: string } | null {
  const i = source ? source.lastIndexOf("|") : -1;
  if (!source || i <= 0 || i === source.length - 1) return null;
  const scope = source.slice(i + 1);
  const network = !scope.includes("/") && scope.split(".").length === 3 ? `${scope}.0/24` : scope;
  return { build: source.slice(0, i), network };
}

export function getSeverityColor(sev: string) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'red';
  if (s === 'medium') return 'orange';
  if (s === 'low') return 'blue';
  return 'gray';
}
