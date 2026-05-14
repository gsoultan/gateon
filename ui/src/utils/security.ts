export function getThreatColor(type: string) {
  const t = (type || '').toLowerCase();
  if (t.includes('waf') || t.includes('sqli') || t.includes('xss')) return 'red.7';
  if (t.includes('bot') || t.includes('scanner')) return 'orange.7';
  if (t.includes('geoip')) return 'blue.7';
  if (t.includes('ddos') || t.includes('flood')) return 'grape.7';
  if (t.includes('brute')) return 'yellow.7';
  return 'cyan.7';
}

export function getSeverityColor(sev: string) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'red';
  if (s === 'medium') return 'orange';
  if (s === 'low') return 'blue';
  return 'gray';
}
