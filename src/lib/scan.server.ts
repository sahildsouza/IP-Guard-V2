import type { SupabaseClient } from "@supabase/supabase-js";

export type Service = "virustotal" | "abuseipdb";
export type IndicatorType = "ip" | "domain" | "hash";
export type Verdict = "malicious" | "suspicious" | "clean" | "unknown";

export type KeyRow = {
  id: string;
  service: Service;
  label: string;
  api_key: string;
  daily_limit: number;
  requests_used: number;
  last_reset_date: string;
  is_active: boolean;
};

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

/** Coerce provider values into a JSON-serializable shape. */
const j = (v: unknown): JsonValue => (v === undefined ? null : (v as JsonValue));

export type CallMeta = {
  service: Service;
  key_label: string | null;
  attempts: number;
  retries: number;
  retry_reasons: string[];
  exhausted: boolean;
  skipped: boolean;
};

export type ScanResult = {
  indicator: string;
  indicator_type: IndicatorType;
  verdict: Verdict;
  malicious_count: number;
  suspicious_count: number;
  harmless_count: number;
  undetected_count: number;
  abuse_score: number | null;
  reputation: number | null;
  summary: Record<string, JsonValue>;
  error: string | null;
  vt_raw: JsonValue;
  abuse_raw: JsonValue;
  calls: CallMeta[];
};

export function istDateString(d = new Date()): string {
  return new Date(d.getTime() + 5.5 * 3600 * 1000).toISOString().slice(0, 10);
}

/** Round-robin pool that skips keys at or above their daily limit. */
export class KeyPool {
  private cursor = 0;
  private consumed = new Map<string, number>();
  readonly keys: KeyRow[];

  constructor(keys: KeyRow[]) {
    const today = istDateString();
    this.keys = keys
      .filter((k) => k.is_active)
      .map((k) =>
        k.last_reset_date < today ? { ...k, requests_used: 0, last_reset_date: today } : k,
      );
  }

  get size() {
    return this.keys.length;
  }

  take(): KeyRow | null {
    for (let i = 0; i < this.keys.length; i++) {
      const key = this.keys[(this.cursor + i) % this.keys.length]!;
      const used = key.requests_used + (this.consumed.get(key.id) ?? 0);
      if (used < key.daily_limit) {
        this.cursor = (this.cursor + i + 1) % this.keys.length;
        this.consumed.set(key.id, (this.consumed.get(key.id) ?? 0) + 1);
        return key;
      }
    }
    return null;
  }

  usage(): { id: string; used: number; requests_used: number; last_reset_date: string }[] {
    return [...this.consumed.entries()].map(([id, used]) => {
      const key = this.keys.find((k) => k.id === id)!;
      return {
        id,
        used,
        requests_used: key.requests_used + used,
        last_reset_date: key.last_reset_date,
      };
    });
  }
}

export async function flushUsage(
  supabase: SupabaseClient,
  pools: KeyPool[],
): Promise<void> {
  const rows = pools.flatMap((p) => p.usage());
  await Promise.all(
    rows.map((r) =>
      supabase
        .from("api_keys")
        .update({
          requests_used: r.requests_used,
          last_reset_date: r.last_reset_date,
          last_used_at: new Date().toISOString(),
        })
        .eq("id", r.id),
    ),
  );
}

type VtStats = {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  timeout?: number;
};

const EMPTY_STATS: VtStats = { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 };

/** Errors worth retrying: temporary rate limits, timeouts and upstream 5xx. */
class TransientError extends Error {
  constructor(
    message: string,
    readonly retryAfterMs: number | null = null,
  ) {
    super(message);
    this.name = "TransientError";
  }
}

const TRANSIENT_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);
const MAX_ATTEMPTS = 4;
const BASE_DELAY_MS = 600;
const MAX_DELAY_MS = 8000;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function retryAfterMs(res: Response): number | null {
  const raw = res.headers.get("retry-after");
  if (!raw) return null;
  const secs = Number(raw);
  if (Number.isFinite(secs)) return Math.min(MAX_DELAY_MS, Math.max(0, secs * 1000));
  const at = Date.parse(raw);
  return Number.isNaN(at) ? null : Math.min(MAX_DELAY_MS, Math.max(0, at - Date.now()));
}

function raiseIfTransient(res: Response, message: string): void {
  if (TRANSIENT_STATUS.has(res.status)) throw new TransientError(message, retryAfterMs(res));
}

async function vtFetch(path: string, key: string) {
  let res: Response;
  try {
    res = await fetch(`https://www.virustotal.com/api/v3/${path}`, {
      headers: { "x-apikey": key, accept: "application/json" },
    });
  } catch (e) {
    throw new TransientError(`VirusTotal network error: ${(e as Error).message}`);
  }
  const body = (await res.json().catch(() => null)) as
    | { data?: { attributes?: Record<string, unknown> }; error?: { message?: string } }
    | null;
  if (!res.ok) {
    if (res.status === 404) return { notFound: true, attributes: null as null, raw: null };
    const message = body?.error?.message ?? `VirusTotal error ${res.status}`;
    raiseIfTransient(res, message);
    throw new Error(message);
  }
  return {
    notFound: false,
    attributes: (body?.data?.attributes ?? {}) as Record<string, unknown>,
    raw: j(body?.data ?? null),
  };
}

async function abuseFetch(ip: string, key: string) {
  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose=`;
  let res: Response;
  try {
    res = await fetch(url, { headers: { Key: key, Accept: "application/json" } });
  } catch (e) {
    throw new TransientError(`AbuseIPDB network error: ${(e as Error).message}`);
  }
  const body = (await res.json().catch(() => null)) as
    | { data?: Record<string, unknown>; errors?: { detail?: string }[] }
    | null;
  if (!res.ok) {
    const message = body?.errors?.[0]?.detail ?? `AbuseIPDB error ${res.status}`;
    raiseIfTransient(res, message);
    throw new Error(message);
  }
  return (body?.data ?? {}) as Record<string, unknown>;
}

/**
 * Run a provider call with exponential backoff. Every attempt draws a fresh key
 * from the pool, so per-key daily quotas are always respected and exhausted
 * keys are skipped automatically.
 */
async function callWithBackoff<T>(
  pool: KeyPool,
  service: Service,
  fn: (key: KeyRow) => Promise<T>,
): Promise<{ value: T | null; meta: CallMeta; error: string | null }> {
  const meta: CallMeta = {
    service,
    key_label: null,
    attempts: 0,
    retries: 0,
    retry_reasons: [],
    exhausted: false,
    skipped: false,
  };
  let lastError: string | null = null;

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    const key = pool.take();
    if (!key) {
      if (meta.attempts === 0) {
        meta.skipped = true;
        meta.exhausted = pool.size > 0;
      } else {
        meta.exhausted = true;
        lastError = `${lastError ?? "Retry required"} · no key left within daily quota`;
      }
      return { value: null, meta, error: lastError };
    }
    meta.attempts++;
    meta.key_label = key.label;
    try {
      return { value: await fn(key), meta, error: null };
    } catch (e) {
      lastError = (e as Error).message;
      if (!(e instanceof TransientError) || attempt === MAX_ATTEMPTS) {
        return { value: null, meta, error: lastError };
      }
      meta.retries++;
      meta.retry_reasons.push(lastError);
      const backoff = Math.min(MAX_DELAY_MS, BASE_DELAY_MS * 2 ** (attempt - 1));
      await sleep((e.retryAfterMs ?? backoff) + Math.random() * 250);
    }
  }
  return { value: null, meta, error: lastError };
}

function num(v: unknown): number {
  return typeof v === "number" ? v : 0;
}

function statsOf(attributes: Record<string, unknown> | null): VtStats {
  const stats = (attributes?.["last_analysis_stats"] ?? {}) as Record<string, unknown>;
  return {
    malicious: num(stats["malicious"]),
    suspicious: num(stats["suspicious"]),
    harmless: num(stats["harmless"]),
    undetected: num(stats["undetected"]),
    timeout: num(stats["timeout"]),
  };
}

function iso(seconds: unknown): string | null {
  return typeof seconds === "number" && seconds > 0
    ? new Date(seconds * 1000).toISOString()
    : null;
}

function verdictOf(stats: VtStats, abuseScore: number | null, found: boolean): Verdict {
  if (stats.malicious >= 1 || (abuseScore ?? 0) >= 50) return "malicious";
  if (stats.suspicious >= 1 || (abuseScore ?? 0) >= 15) return "suspicious";
  if (!found) return "unknown";
  return "clean";
}

export type ScanContext = {
  vt: KeyPool;
  abuse: KeyPool;
};

export async function scanOne(
  indicator: string,
  type: IndicatorType,
  ctx: ScanContext,
): Promise<ScanResult> {
  const errors: string[] = [];
  const calls: CallMeta[] = [];
  let attributes: Record<string, unknown> | null = null;
  let found = false;
  let abuse: Record<string, unknown> | null = null;
  let vtRaw: JsonValue = null;

  const path =
    type === "ip"
      ? `ip_addresses/${encodeURIComponent(indicator)}`
      : type === "domain"
        ? `domains/${encodeURIComponent(indicator)}`
        : `files/${encodeURIComponent(indicator)}`;

  const vtCall = await callWithBackoff(ctx.vt, "virustotal", (key) => vtFetch(path, key.api_key));
  calls.push(vtCall.meta);
  if (vtCall.value) {
    attributes = vtCall.value.attributes;
    found = !vtCall.value.notFound;
    vtRaw = vtCall.value.raw ?? null;
  } else if (vtCall.meta.skipped) {
    errors.push(
      ctx.vt.size === 0
        ? "No VirusTotal key configured"
        : "All VirusTotal keys reached their daily limit",
    );
  } else if (vtCall.error) {
    errors.push(
      `VirusTotal: ${vtCall.error}${vtCall.meta.retries ? ` (after ${vtCall.meta.retries} retries)` : ""}`,
    );
  }

  if (type === "ip") {
    const abuseCall = await callWithBackoff(ctx.abuse, "abuseipdb", (key) =>
      abuseFetch(indicator, key.api_key),
    );
    calls.push(abuseCall.meta);
    if (abuseCall.value) {
      abuse = abuseCall.value;
      found = true;
    } else if (abuseCall.meta.skipped) {
      errors.push(
        ctx.abuse.size === 0
          ? "No AbuseIPDB key configured"
          : "All AbuseIPDB keys reached their daily limit",
      );
    } else if (abuseCall.error) {
      errors.push(
        `AbuseIPDB: ${abuseCall.error}${abuseCall.meta.retries ? ` (after ${abuseCall.meta.retries} retries)` : ""}`,
      );
    }
  }


  const stats = statsOf(attributes);
  const abuseScore =
    abuse && typeof abuse["abuseConfidenceScore"] === "number"
      ? (abuse["abuseConfidenceScore"] as number)
      : null;
  const reputation =
    attributes && typeof attributes["reputation"] === "number"
      ? (attributes["reputation"] as number)
      : null;

  const engines = Object.keys(
    (attributes?.["last_analysis_results"] ?? {}) as Record<string, unknown>,
  ).length;

  const summary: Record<string, JsonValue> = {
    engines_total:
      engines || stats.malicious + stats.suspicious + stats.harmless + stats.undetected,
    vt_found: found && !!attributes,
    last_analysis_date: iso(attributes?.["last_analysis_date"]),
  };

  if (type === "ip") {
    Object.assign(summary, {
      isp: abuse?.["isp"] ?? attributes?.["as_owner"] ?? null,
      country: abuse?.["countryCode"] ?? attributes?.["country"] ?? null,
      usage_type: abuse?.["usageType"] ?? null,
      domain: abuse?.["domain"] ?? null,
      hostnames: abuse?.["hostnames"] ?? null,
      is_tor: abuse?.["isTor"] ?? null,
      total_reports: abuse?.["totalReports"] ?? null,
      last_reported_at: abuse?.["lastReportedAt"] ?? null,
      asn: attributes?.["asn"] ?? null,
      network: attributes?.["network"] ?? null,
    });
  } else if (type === "domain") {
    const cats = (attributes?.["categories"] ?? {}) as Record<string, string>;
    Object.assign(summary, {
      registrar: attributes?.["registrar"] ?? null,
      creation_date: iso(attributes?.["creation_date"]),
      categories: Object.entries(cats).map(([vendor, value]) => `${value} (${vendor})`),
      tld: attributes?.["tld"] ?? null,
    });
  } else {
    Object.assign(summary, {
      file_type: attributes?.["type_description"] ?? attributes?.["type_tag"] ?? null,
      size: attributes?.["size"] ?? null,
      meaningful_name: attributes?.["meaningful_name"] ?? attributes?.["names"] ?? null,
      threat_label: j(
        ((attributes?.["popular_threat_classification"] ?? {}) as Record<string, unknown>)[
          "suggested_threat_label"
        ] ?? null,
      ),
      threat_categories: (
        (((attributes?.["popular_threat_classification"] ?? {}) as Record<string, unknown>)[
          "popular_threat_category"
        ] ?? []) as { value?: string }[]
      ).map((c) => c.value ?? ""),
      first_seen: iso(attributes?.["first_submission_date"]),
      sha256: attributes?.["sha256"] ?? null,
      md5: attributes?.["md5"] ?? null,
    });
  }

  return {
    indicator,
    indicator_type: type,
    verdict: verdictOf(stats, abuseScore, found),
    malicious_count: stats.malicious,
    suspicious_count: stats.suspicious,
    harmless_count: stats.harmless,
    undetected_count: stats.undetected,
    abuse_score: abuseScore,
    reputation,
    summary,
    error: errors.length ? errors.join(" · ") : null,
    vt_raw: vtRaw,
    abuse_raw: j(abuse),
    calls,
  };
}
