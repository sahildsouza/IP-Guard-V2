import { createFileRoute, Link } from "@tanstack/react-router";
import { useMemo } from "react";
import {
  Activity,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  KeyRound,
  ArrowUpRight,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { AppShell, PageHeader } from "@/components/app-shell";
import { StatTile, UsageBar, SERVICE_META, effectiveUsed } from "@/components/usage";
import { ResultCard } from "@/components/result-card";
import { useApiKeys, useScans } from "@/hooks/use-app-data";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { formatCountdown, msUntilIstReset } from "@/lib/indicators";

export const Route = createFileRoute("/_authenticated/dashboard")({
  head: () => ({
    meta: [
      { title: "Dashboard — IP-Guard Threat Console" },
      {
        name: "description",
        content:
          "Recent indicator scans, threat counts and aggregate VirusTotal / AbuseIPDB quota usage.",
      },
      { property: "og:title", content: "Dashboard — IP-Guard Threat Console" },
      {
        property: "og:description",
        content: "Track scan volume, malicious hits and remaining daily API quota.",
      },
    ],
  }),
  component: Dashboard,
});

function Dashboard() {
  const keys = useApiKeys();
  const scans = useScans(200);

  const usage = useMemo(() => {
    const rows = keys.data ?? [];
    return (["virustotal", "abuseipdb"] as const).map((service) => {
      const pool = rows.filter((k) => k.service === service);
      const used = pool.reduce((n, k) => n + effectiveUsed(k), 0);
      const limit = pool.reduce((n, k) => n + (k.is_active ? k.daily_limit : 0), 0);
      const exhausted = pool.filter((k) => k.is_active && effectiveUsed(k) >= k.daily_limit).length;
      return { service, pool, used, limit, exhausted, active: pool.filter((k) => k.is_active).length };
    });
  }, [keys.data]);

  const stats = useMemo(() => {
    const rows = scans.data ?? [];
    const today = new Date().toISOString().slice(0, 10);
    return {
      total: rows.length,
      today: rows.filter((r) => r.created_at.slice(0, 10) === today).length,
      malicious: rows.filter((r) => r.verdict === "malicious").length,
      suspicious: rows.filter((r) => r.verdict === "suspicious").length,
      clean: rows.filter((r) => r.verdict === "clean").length,
    };
  }, [scans.data]);

  const trend = useMemo(() => {
    const rows = scans.data ?? [];
    const days = Array.from({ length: 7 }, (_, i) => {
      const d = new Date(Date.now() - (6 - i) * 86400000);
      return d.toISOString().slice(0, 10);
    });
    return days.map((day) => {
      const dayRows = rows.filter((r) => r.created_at.slice(0, 10) === day);
      return {
        day: day.slice(5),
        scans: dayRows.length,
        threats: dayRows.filter((r) => r.verdict === "malicious" || r.verdict === "suspicious")
          .length,
      };
    });
  }, [scans.data]);

  const typeCounts = useMemo(() => {
    const rows = scans.data ?? [];
    return (["ip", "domain", "hash"] as const).map((t) => ({
      type: t,
      count: rows.filter((r) => r.indicator_type === t).length,
    }));
  }, [scans.data]);

  const noKeys = !keys.isLoading && (keys.data ?? []).length === 0;

  return (
    <AppShell>
      <PageHeader
        title="Dashboard"
        description="Scan activity, threat breakdown and daily quota consumption."
        actions={
          <Button asChild size="sm" className="gap-1.5">
            <Link to="/checker">
              New scan <ArrowUpRight className="size-3.5" />
            </Link>
          </Button>
        }
      />

      {noKeys && (
        <div className="mb-4 flex flex-wrap items-center gap-3 rounded-lg border border-warn/30 bg-warn/10 px-3.5 py-3">
          <AlertTriangle className="size-4 text-warn" />
          <p className="flex-1 text-[13px] text-warn">
            No API keys configured yet — add VirusTotal and AbuseIPDB keys to start scanning.
          </p>
          <Button asChild size="sm" variant="outline">
            <Link to="/settings">Add keys</Link>
          </Button>
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile label="Scans today" value={stats.today} icon={Activity} hint={`${stats.total} in history`} />
        <StatTile label="Malicious" value={stats.malicious} tone="danger" icon={ShieldAlert} hint="across recent scans" />
        <StatTile label="Suspicious" value={stats.suspicious} tone="warn" icon={AlertTriangle} hint="needs review" />
        <StatTile label="Clean" value={stats.clean} tone="safe" icon={ShieldCheck} hint="no detections" />
      </div>

      <div className="mt-3 grid gap-3 lg:grid-cols-3">
        <div className="panel p-4 lg:col-span-2">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold">Scan activity — last 7 days</h2>
            <span className="text-[11px] text-muted-foreground">scans vs. threats</span>
          </div>
          <div className="h-[190px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trend} margin={{ top: 4, right: 4, bottom: 0, left: -22 }}>
                <defs>
                  <linearGradient id="gScans" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--primary)" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="var(--primary)" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gThreats" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--danger)" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="var(--danger)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                <XAxis
                  dataKey="day"
                  tick={{ fontSize: 11, fill: "var(--muted-foreground)" }}
                  stroke="var(--border)"
                />
                <YAxis
                  allowDecimals={false}
                  tick={{ fontSize: 11, fill: "var(--muted-foreground)" }}
                  stroke="var(--border)"
                />
                <Tooltip
                  contentStyle={{
                    background: "var(--popover)",
                    border: "1px solid var(--border)",
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="scans"
                  stroke="var(--primary)"
                  fill="url(#gScans)"
                  strokeWidth={2}
                />
                <Area
                  type="monotone"
                  dataKey="threats"
                  stroke="var(--danger)"
                  fill="url(#gThreats)"
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="panel p-4">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold">API quota today</h2>
            <span className="font-mono text-[10.5px] text-muted-foreground">
              resets in {formatCountdown(msUntilIstReset())}
            </span>
          </div>
          <div className="space-y-4">
            {usage.map((u) => {
              const meta = SERVICE_META[u.service];
              return (
                <div key={u.service}>
                  <div className="mb-1.5 flex items-baseline justify-between gap-2">
                    <span className="text-[13px] font-medium">{meta.name}</span>
                    <span className="font-mono text-[11.5px] text-muted-foreground">
                      {u.used.toLocaleString()} / {u.limit.toLocaleString()}
                    </span>
                  </div>
                  <UsageBar used={u.used} limit={u.limit} barClassName={meta.bar} />
                  <p className="mt-1.5 text-[11px] text-muted-foreground">
                    {u.active} active {u.active === 1 ? "key" : "keys"} ·{" "}
                    {Math.max(0, u.limit - u.used).toLocaleString()} remaining
                    {u.exhausted > 0 && (
                      <span className="text-warn"> · {u.exhausted} exhausted</span>
                    )}
                  </p>
                </div>
              );
            })}
          </div>

          <div className="mt-4 border-t border-border pt-3">
            <h3 className="mb-2 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Indicator mix
            </h3>
            <div className="space-y-1.5">
              {typeCounts.map((t) => (
                <div key={t.type} className="flex items-center justify-between text-[12.5px]">
                  <span className="capitalize text-muted-foreground">
                    {t.type === "ip" ? "IP addresses" : t.type === "domain" ? "Domains" : "File hashes"}
                  </span>
                  <span className="font-mono">{t.count}</span>
                </div>
              ))}
            </div>
          </div>

          <Button asChild variant="ghost" size="sm" className="mt-3 w-full gap-1.5 text-[12.5px]">
            <Link to="/settings">
              <KeyRound className="size-3.5" /> Manage keys
            </Link>
          </Button>
        </div>
      </div>

      <div className="mt-5">
        <div className="mb-2.5 flex items-center justify-between">
          <h2 className="text-sm font-semibold">Recent scans</h2>
          <span className="text-[11px] text-muted-foreground">latest 12 indicators</span>
        </div>
        {scans.isLoading ? (
          <div className="space-y-2">
            {[0, 1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-11 w-full" />
            ))}
          </div>
        ) : (scans.data ?? []).length === 0 ? (
          <div className="panel p-8 text-center">
            <p className="text-[13px] text-muted-foreground">
              No scans yet. Run your first lookup from the Checker.
            </p>
            <Button asChild size="sm" className="mt-3">
              <Link to="/checker">Open Checker</Link>
            </Button>
          </div>
        ) : (
          <div className="space-y-2">
            {(scans.data ?? []).slice(0, 12).map((row, i) => (
              <ResultCard key={row.id} index={i + 1} result={row} />
            ))}
          </div>
        )}
      </div>
    </AppShell>
  );
}
