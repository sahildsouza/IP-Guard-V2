export type IndicatorType = "ip" | "domain" | "hash";

const IPV4 =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV6 = /^(?:[a-f\d]{1,4}:){2,7}[a-f\d]{0,4}$/i;
const HASH = /^(?:[a-f\d]{32}|[a-f\d]{40}|[a-f\d]{64})$/i;
const DOMAIN = /^(?=.{1,253}$)(?!-)[a-z\d-]{1,63}(?<!-)(\.(?!-)[a-z\d-]{1,63}(?<!-))+$/i;

export function detectType(raw: string): IndicatorType | null {
  const value = normalizeIndicator(raw);
  if (!value) return null;
  if (IPV4.test(value) || IPV6.test(value)) return "ip";
  if (HASH.test(value)) return "hash";
  if (DOMAIN.test(value)) return "domain";
  return null;
}

export function normalizeIndicator(raw: string): string {
  let value = raw.trim().replace(/^["'`]|["'`,;]+$/g, "");
  value = value.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".");
  value = value.replace(/^h(?:tt|xx)ps?:\/\//i, "");
  value = value.replace(/^www\./i, "").replace(/\/.*$/, "");
  return value.trim();
}

export type ParsedIndicator = {
  value: string;
  type: IndicatorType | null;
  raw: string;
};

export function parseIndicatorList(input: string): ParsedIndicator[] {
  const seen = new Set<string>();
  const out: ParsedIndicator[] = [];
  for (const raw of input.split(/[\n\r,;\t]+/)) {
    if (!raw.trim()) continue;
    const value = normalizeIndicator(raw);
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ value, type: detectType(value), raw: raw.trim() });
  }
  return out;
}

export const INDICATOR_LABEL: Record<IndicatorType, string> = {
  ip: "IP address",
  domain: "Domain",
  hash: "File hash",
};

export const SERVICE_LIMITS = { virustotal: 500, abuseipdb: 1000 } as const;

export function istNow(): Date {
  return new Date(Date.now() + 5.5 * 3600 * 1000);
}

/** Milliseconds until the next 12:00 AM IST reset. */
export function msUntilIstReset(): number {
  const ist = istNow();
  const next = Date.UTC(
    ist.getUTCFullYear(),
    ist.getUTCMonth(),
    ist.getUTCDate() + 1,
    0,
    0,
    0,
  );
  return next - ist.getTime();
}

export function formatCountdown(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  return `${String(h).padStart(2, "0")}h ${String(m).padStart(2, "0")}m ${String(s).padStart(2, "0")}s`;
}

export function maskKey(key: string): string {
  if (key.length <= 10) return `${key.slice(0, 2)}••••`;
  return `${key.slice(0, 6)}••••••${key.slice(-4)}`;
}

export type Verdict = "malicious" | "suspicious" | "clean" | "unknown";

export const VERDICT_STYLE: Record<Verdict, { label: string; className: string }> = {
  malicious: { label: "Malicious", className: "bg-danger/15 text-danger border-danger/30" },
  suspicious: { label: "Suspicious", className: "bg-warn/15 text-warn border-warn/30" },
  clean: { label: "Clean", className: "bg-safe/15 text-safe border-safe/30" },
  unknown: {
    label: "Unknown",
    className: "bg-muted text-muted-foreground border-border",
  },
};

export function istResetLabel(): string {
  return "12:00 AM IST";
}

/** Expand a 2-letter country code into its full country name. */
export function countryName(code: unknown): string | null {
  if (typeof code !== "string") return null;
  const raw = code.trim();
  if (!raw) return null;
  if (raw.length !== 2) return raw;
  try {
    const display = new Intl.DisplayNames(["en"], { type: "region" });
    const name = display.of(raw.toUpperCase());
    return name && name.toUpperCase() !== raw.toUpperCase()
      ? `${name} (${raw.toUpperCase()})`
      : raw.toUpperCase();
  } catch {
    return raw.toUpperCase();
  }
}
