// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// The IP filter's lists hold IP addresses and CIDRs, nothing else. The gateway
// refuses a save with any other entry (ADR 0047); this says which before the
// request, so the operator is not left reading a server error.

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

function isIPv6(value: string): boolean {
  if (!value.includes(":") || !/^[0-9a-fA-F:.]+$/.test(value)) return false;
  try {
    return new URL(`http://[${value}]/`).hostname.length > 2;
  } catch {
    return false;
  }
}

function isAddress(value: string): boolean {
  return IPV4.test(value) || isIPv6(value);
}

export function isIPOrCIDR(entry: string): boolean {
  const value = entry.trim();
  const slash = value.indexOf("/");
  if (slash < 0) return isAddress(value);
  const addr = value.slice(0, slash);
  const bits = value.slice(slash + 1);
  if (!/^\d{1,3}$/.test(bits) || !isAddress(addr)) return false;
  return Number(bits) <= (addr.includes(":") ? 128 : 32);
}

// ipListError names the entries the gateway would refuse, or null.
export function ipListError(entries: string[]): string | null {
  const bad = entries.filter((e) => e.trim() !== "" && !isIPOrCIDR(e));
  if (bad.length === 0) return null;
  return `Not an IP address or CIDR: ${bad.join(", ")}. Wildcards and ranges are not supported; write a CIDR such as 10.0.0.0/24.`;
}
