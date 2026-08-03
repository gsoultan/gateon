export function formatCompact(num: number | undefined | null): string {
  if (num === undefined || num === null || isNaN(num as number)) return "0";
  const n = num as number;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)}K`;
  return n.toLocaleString();
}

export function formatBytes(num: number | undefined | null): string {
  if (num === undefined || num === null || isNaN(num as number)) return "0 B";
  const n = num as number;
  if (n >= 1024 * 1024 * 1024) return `${(n / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${Math.round(n)} B`;
}

export function safeToFixed(val: number | undefined | null, decimals = 1): string {
  if (val === undefined || val === null || isNaN(Number(val))) return "0";
  return Number(val).toFixed(decimals);
}

export function safeToLocaleString(val: number | undefined | null): string {
  if (val === undefined || val === null || isNaN(Number(val))) return "0";
  return Number(val).toLocaleString();
}

export function formatHourLabel(ts: number): string {
  const date = new Date(ts);
  const month = `${date.getMonth() + 1}`.padStart(2, "0");
  const day = `${date.getDate()}`.padStart(2, "0");
  const hour = `${date.getHours()}`.padStart(2, "0");
  return `${month}/${day} ${hour}:00`;
}

export function getCountryFlag(countryCode: string): string {
  if (!countryCode || countryCode.length !== 2 || countryCode === "XX") {
    return "🌐";
  }
  const codePoints = countryCode
    .toUpperCase()
    .split("")
    .map((char) => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}
