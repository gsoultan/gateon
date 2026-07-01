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

export function getSeverityColor(sev: string) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'red';
  if (s === 'medium') return 'orange';
  if (s === 'low') return 'blue';
  return 'gray';
}
