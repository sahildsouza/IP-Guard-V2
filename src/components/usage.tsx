import { cn } from "@/lib/utils";
import type { ApiKeyRow } from "@/hooks/use-app-data";
import { istNow } from "@/lib/indicators";

export const SERVICE_META = {
  virustotal: { name: "VirusTotal", limit: 500, accent: "text-primary", bar: "bg-primary" },
  abuseipdb: { name: "AbuseIPDB", limit: 1000, accent: "text-chart-5", bar: "bg-chart-5" },
} as const;

export function effectiveUsed(key: ApiKeyRow): number {
  const today = istNow().toISOString().slice(0, 10);
  return key.last_reset_date < today ? 0 : key.requests_used;
}

export function UsageBar({
  used,
  limit,
  className,
  barClassName,
}: {
  used: number;
  limit: number;
  className?: string;
  barClassName?: string;
}) {
  const pct = limit > 0 ? Math.min(100, (used / limit) * 100) : 0;
  const tone = pct >= 100 ? "bg-danger" : pct >= 80 ? "bg-warn" : (barClassName ?? "bg-primary");
  return (
    <div className={cn("h-1.5 w-full overflow-hidden rounded-full bg-secondary", className)}>
      <div
        className={cn("h-full rounded-full transition-[width] duration-500 ease-out", tone)}
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}

export function StatTile({
  label,
  value,
  hint,
  tone = "default",
  icon: Icon,
}: {
  label: string;
  value: string | number;
  hint?: string;
  tone?: "default" | "danger" | "warn" | "safe";
  icon?: React.ComponentType<{ className?: string }>;
}) {
  const toneClass = {
    default: "text-foreground",
    danger: "text-danger",
    warn: "text-warn",
    safe: "text-safe",
  }[tone];
  return (
    <div className="panel p-3.5 transition-colors duration-200 hover:border-primary/30">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          {label}
        </p>
        {Icon && <Icon className={cn("size-3.5", toneClass)} />}
      </div>
      <p className={cn("mt-1.5 font-display text-2xl font-semibold tabular-nums", toneClass)}>
        {value}
      </p>
      {hint && <p className="mt-0.5 text-[11px] text-muted-foreground">{hint}</p>}
    </div>
  );
}
