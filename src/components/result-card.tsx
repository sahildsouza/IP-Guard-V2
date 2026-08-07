import { useState } from "react";
import { ChevronDown, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";
import { VERDICT_STYLE, countryName, type Verdict } from "@/lib/indicators";
import { Badge } from "@/components/ui/badge";

export type DisplayResult = {
  indicator: string;
  indicator_type: "ip" | "domain" | "hash";
  verdict: string;
  malicious_count: number;
  suspicious_count: number;
  harmless_count: number;
  abuse_score: number | null;
  reputation: number | null;
  summary: Record<string, unknown>;
  error: string | null;
  created_at?: string;
  vt_raw?: unknown;
  abuse_raw?: unknown;
  calls?: {
    service: string;
    key_label: string | null;
    attempts: number;
    retries: number;
    retry_reasons?: string[];
    exhausted?: boolean;
    skipped?: boolean;
  }[];
};

const TYPE_LABEL = { ip: "IP", domain: "DOMAIN", hash: "HASH" } as const;

function str(v: unknown): string | null {
  if (v == null || v === "") return null;
  if (Array.isArray(v)) return v.length ? v.slice(0, 6).join(", ") : null;
  if (typeof v === "object") return null;
  if (typeof v === "boolean") return v ? "Yes" : "No";
  return String(v);
}

function date(v: unknown): string | null {
  const s = str(v);
  if (!s) return null;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? s : d.toISOString().slice(0, 10);
}

function fieldsFor(r: DisplayResult): [string, string | null][] {
  const s = r.summary ?? {};
  const engines = str(s["engines_total"]) ?? "0";
  const ratio = `${r.malicious_count}/${engines}`;
  if (r.indicator_type === "ip") {
    return [
      ["Abuse score", r.abuse_score == null ? null : `${r.abuse_score}%`],
      ["VT detections", ratio],
      ["Reputation", r.reputation == null ? null : String(r.reputation)],
      ["ISP", str(s["isp"])],
      ["Country", countryName(s["country"])],
      ["Usage type", str(s["usage_type"])],
      ["Domain", str(s["domain"])],
      ["Hostnames", str(s["hostnames"])],
      ["ASN", str(s["asn"])],
      ["Network", str(s["network"])],
      ["Total reports", str(s["total_reports"])],
      ["Last reported", date(s["last_reported_at"])],
      ["Tor exit node", str(s["is_tor"])],
      ["Last analysis", date(s["last_analysis_date"])],
    ];
  }
  if (r.indicator_type === "domain") {
    return [
      ["VT detections", ratio],
      ["Reputation", r.reputation == null ? null : String(r.reputation)],
      ["Registrar", str(s["registrar"])],
      ["Created", date(s["creation_date"])],
      ["TLD", str(s["tld"])],
      ["Categories", str(s["categories"])],
      ["Harmless", String(r.harmless_count)],
      ["Suspicious", String(r.suspicious_count)],
      ["Last analysis", date(s["last_analysis_date"])],
    ];
  }
  return [
    ["Detection ratio", ratio],
    ["Threat label", str(s["threat_label"])],
    ["Classification", str(s["threat_categories"])],
    ["File type", str(s["file_type"])],
    ["Size", s["size"] ? `${Number(s["size"]).toLocaleString()} bytes` : null],
    ["Name", str(s["meaningful_name"])],
    ["First seen", date(s["first_seen"])],
    ["Last analysis", date(s["last_analysis_date"])],
    ["SHA-256", str(s["sha256"])],
    ["MD5", str(s["md5"])],
  ];
}

export function ResultCard({ result, index = 0 }: { result: DisplayResult; index?: number }) {
  const [open, setOpen] = useState(index < 1);
  const verdict = (result.verdict as Verdict) in VERDICT_STYLE ? (result.verdict as Verdict) : "unknown";
  const style = VERDICT_STYLE[verdict];
  const fields = fieldsFor(result).filter(([, v]) => v != null);

  return (
    <div
      className="panel animate-rise overflow-hidden"
      style={{ animationDelay: `${Math.min(index, 8) * 30}ms` }}
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2.5 px-3.5 py-2.5 text-left transition-colors duration-200 hover:bg-accent/40"
      >
        <span className="rounded border border-border bg-secondary px-1.5 py-0.5 font-mono text-[10px] font-semibold tracking-wider text-muted-foreground">
          {TYPE_LABEL[result.indicator_type]}
        </span>
        <span className="min-w-0 flex-1 truncate font-mono text-[13px] font-medium">
          {result.indicator}
        </span>
        {result.abuse_score != null && (
          <span className="hidden shrink-0 font-mono text-[11px] text-muted-foreground sm:inline">
            abuse {result.abuse_score}%
          </span>
        )}
        <span className="shrink-0 font-mono text-[11px] text-muted-foreground">
          {result.malicious_count}/{str(result.summary?.["engines_total"]) ?? "0"}
        </span>
        <Badge variant="outline" className={cn("shrink-0 text-[10px]", style.className)}>
          {style.label}
        </Badge>
        <ChevronDown
          className={cn(
            "size-3.5 shrink-0 text-muted-foreground transition-transform duration-200",
            open && "rotate-180",
          )}
        />
      </button>

      {open && (
        <div className="border-t border-border px-3.5 py-3">
          {result.error && (
            <div className="mb-3 flex items-start gap-2 rounded-md border border-warn/30 bg-warn/10 px-2.5 py-2 text-[12px] text-warn">
              <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
              <span>{result.error}</span>
            </div>
          )}
          {fields.length === 0 ? (
            <p className="text-[13px] text-muted-foreground">No data returned for this indicator.</p>
          ) : (
            <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-2 lg:grid-cols-3">
              {fields.map(([label, value]) => (
                <div key={label} className="min-w-0">
                  <dt className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                    {label}
                  </dt>
                  <dd className="truncate font-mono text-[12.5px]" title={value ?? undefined}>
                    {value}
                  </dd>
                </div>
              ))}
            </dl>
          )}
        </div>
      )}
    </div>
  );
}
