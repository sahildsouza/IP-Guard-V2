import type { DisplayResult } from "@/components/result-card";

export type ResultCallMeta = {
  service: string;
  key_label: string | null;
  attempts: number;
  retries: number;
  retry_reasons?: string[];
  exhausted?: boolean;
  skipped?: boolean;
};

const flat = (v: unknown): string => {
  if (v == null) return "";
  if (Array.isArray(v)) return v.map((x) => flat(x)).filter(Boolean).join("; ");
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
};

function callsOf(r: DisplayResult): ResultCallMeta[] {
  const fromResult = (r as { calls?: ResultCallMeta[] }).calls;
  if (Array.isArray(fromResult)) return fromResult;
  const fromSummary = (r.summary as { calls?: ResultCallMeta[] } | undefined)?.calls;
  return Array.isArray(fromSummary) ? fromSummary : [];
}

function callFor(r: DisplayResult, service: string): ResultCallMeta | undefined {
  return callsOf(r).find((c) => c.service === service);
}

/** One flat row per result: verdict data, provider metadata and raw payloads. */
export function toExportRow(r: DisplayResult): Record<string, string | number> {
  const s = (r.summary ?? {}) as Record<string, unknown>;
  const vt = callFor(r, "virustotal");
  const abuse = callFor(r, "abuseipdb");
  const raw = r as unknown as { vt_raw?: unknown; abuse_raw?: unknown };

  return {
    indicator: r.indicator,
    detected_type: r.indicator_type,
    verdict: r.verdict,
    malicious: r.malicious_count,
    suspicious: r.suspicious_count,
    harmless: r.harmless_count,
    engines_total: flat(s["engines_total"]),
    abuse_score: r.abuse_score ?? "",
    reputation: r.reputation ?? "",
    isp: flat(s["isp"]),
    country: flat(s["country"]),
    usage_type: flat(s["usage_type"]),
    domain: flat(s["domain"]),
    hostnames: flat(s["hostnames"]),
    asn: flat(s["asn"]),
    network: flat(s["network"]),
    total_reports: flat(s["total_reports"]),
    last_reported_at: flat(s["last_reported_at"]),
    registrar: flat(s["registrar"]),
    creation_date: flat(s["creation_date"]),
    tld: flat(s["tld"]),
    categories: flat(s["categories"]),
    file_type: flat(s["file_type"]),
    file_size: flat(s["size"]),
    file_name: flat(s["meaningful_name"]),
    threat_label: flat(s["threat_label"]),
    threat_categories: flat(s["threat_categories"]),
    first_seen: flat(s["first_seen"]),
    sha256: flat(s["sha256"]),
    md5: flat(s["md5"]),
    last_analysis_date: flat(s["last_analysis_date"]),
    vt_key_label: flat(vt?.key_label),
    vt_requests_used: vt?.attempts ?? 0,
    vt_retries: vt?.retries ?? 0,
    vt_retry_reasons: flat(vt?.retry_reasons),
    vt_quota_exhausted: vt ? String(Boolean(vt.exhausted)) : "",
    abuse_key_label: flat(abuse?.key_label),
    abuse_requests_used: abuse?.attempts ?? 0,
    abuse_retries: abuse?.retries ?? 0,
    abuse_retry_reasons: flat(abuse?.retry_reasons),
    abuse_quota_exhausted: abuse ? String(Boolean(abuse.exhausted)) : "",
    error: r.error ?? "",
    scanned_at: r.created_at ?? new Date().toISOString(),
    vt_raw_json: raw.vt_raw ? JSON.stringify(raw.vt_raw) : "",
    abuse_raw_json: raw.abuse_raw ? JSON.stringify(raw.abuse_raw) : "",
  };
}

function download(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function stamp(): string {
  return new Date().toISOString().replace(/[:T]/g, "-").slice(0, 16);
}

export function exportResultsCsv(results: DisplayResult[]) {
  const rows = results.map(toExportRow);
  const headers = Object.keys(rows[0] ?? {});
  const escape = (v: string | number) => `"${String(v).replace(/"/g, '""')}"`;
  const csv = [
    headers.join(","),
    ...rows.map((row) => headers.map((h) => escape(row[h] ?? "")).join(",")),
  ].join("\r\n");
  download(new Blob([`\uFEFF${csv}`], { type: "text/csv;charset=utf-8" }), `scan-results-${stamp()}.csv`);
}

export async function exportResultsXlsx(results: DisplayResult[]) {
  const XLSX = await import("xlsx");
  const rows = results.map(toExportRow);
  const sheet = XLSX.utils.json_to_sheet(rows);
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, sheet, "Results");
  const out = XLSX.write(wb, { bookType: "xlsx", type: "array" }) as ArrayBuffer;
  download(
    new Blob([out], {
      type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }),
    `scan-results-${stamp()}.xlsx`,
  );
}
