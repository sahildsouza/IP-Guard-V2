import { createFileRoute, Link } from "@tanstack/react-router";
import { useMemo, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { toast } from "sonner";
import {
  Loader2,
  Search,
  Upload,
  FileSpreadsheet,
  X,
  ShieldAlert,
  AlertTriangle,
  Download,
  CheckCircle2,
  Clock,
} from "lucide-react";
import { AppShell, PageHeader } from "@/components/app-shell";
import { ResultCard, type DisplayResult } from "@/components/result-card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";
import { supabase } from "@/integrations/supabase/client";
import { runScan } from "@/lib/scan.functions";
import { exportResultsCsv, exportResultsXlsx } from "@/lib/export-results";
import {
  detectType,
  normalizeIndicator,
  parseIndicatorList,
  type IndicatorType,
} from "@/lib/indicators";

export const Route = createFileRoute("/_authenticated/checker")({
  head: () => ({
    meta: [
      { title: "Checker — Scan IPs, Domains & Hashes" },
      {
        name: "description",
        content:
          "Run single or bulk indicator lookups against VirusTotal and AbuseIPDB, from pasted lists or Excel uploads.",
      },
      { property: "og:title", content: "Checker — Scan IPs, Domains & Hashes" },
      {
        property: "og:description",
        content: "Auto-detect indicator types and scan in bulk with rotating API keys.",
      },
    ],
  }),
  component: Checker,
});

const TYPES: { value: IndicatorType | "auto"; label: string }[] = [
  { value: "auto", label: "Auto-detect" },
  { value: "ip", label: "IP address" },
  { value: "domain", label: "Domain" },
  { value: "hash", label: "File hash" },
];

const MAX_BATCH = 200;
const CHUNK_SIZE = 4;

type VerdictFilter = "all" | "malicious" | "suspicious" | "clean" | "unknown";

const VERDICT_FILTERS: { value: VerdictFilter; label: string }[] = [
  { value: "all", label: "All" },
  { value: "malicious", label: "Malicious" },
  { value: "suspicious", label: "Suspicious" },
  { value: "clean", label: "Clean" },
  { value: "unknown", label: "Unknown" },
];

type QueueStatus = "pending" | "scanning" | "done" | "error" | "cancelled";
type QueueItem = {
  value: string;
  type: IndicatorType;
  status: QueueStatus;
  verdict?: DisplayResult["verdict"];
};

function Checker() {
  const scan = useServerFn(runScan);
  const queryClient = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const cancelRef = useRef(false);

  const [type, setType] = useState<IndicatorType | "auto">("auto");
  const [mode, setMode] = useState<"single" | "bulk">("single");
  const [single, setSingle] = useState("");
  const [bulkText, setBulkText] = useState("");
  const [fileName, setFileName] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState<DisplayResult[]>([]);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [queue, setQueue] = useState<QueueItem[]>([]);
  const [cancelling, setCancelling] = useState(false);
  const [query, setQuery] = useState("");
  const [verdictFilter, setVerdictFilter] = useState<VerdictFilter>("all");

  const processedCount = queue.filter((q) => q.status !== "pending" && q.status !== "scanning")
    .length;
  const cancelledCount = queue.filter((q) => q.status === "cancelled").length;

  const filteredResults = useMemo(() => {
    const q = query.trim().toLowerCase();
    return results.filter((r) => {
      if (verdictFilter !== "all" && r.verdict !== verdictFilter) return false;
      if (!q) return true;
      const haystack = [
        r.indicator,
        r.indicator_type,
        r.verdict,
        r.error ?? "",
        ...Object.values(r.summary ?? {}).map((v) =>
          v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v),
        ),
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(q);
    });
  }, [results, query, verdictFilter]);

  const parsed = useMemo(() => {
    if (mode === "single") {
      const value = normalizeIndicator(single);
      if (!value) return [];
      return [{ value, type: type === "auto" ? detectType(value) : type }];
    }
    return parseIndicatorList(bulkText).map((p) => ({
      value: p.value,
      type: type === "auto" ? p.type : type,
    }));
  }, [mode, single, bulkText, type]);

  const valid = parsed.filter((p): p is { value: string; type: IndicatorType } => p.type !== null);
  const invalid = parsed.length - valid.length;

  const counts = useMemo(
    () => ({
      ip: valid.filter((v) => v.type === "ip").length,
      domain: valid.filter((v) => v.type === "domain").length,
      hash: valid.filter((v) => v.type === "hash").length,
    }),
    [valid],
  );

  async function handleFile(file: File) {
    if (!file.name.toLowerCase().endsWith(".xlsx")) {
      toast.error("Please upload an .xlsx file.");
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      toast.error("File must be under 5 MB.");
      return;
    }
    try {
      const XLSX = await import("xlsx");
      const buffer = await file.arrayBuffer();
      const wb = XLSX.read(buffer, { type: "array" });
      const values: string[] = [];
      for (const sheetName of wb.SheetNames) {
        const sheet = wb.Sheets[sheetName];
        if (!sheet) continue;
        const rows = XLSX.utils.sheet_to_json<unknown[]>(sheet, { header: 1, blankrows: false });
        for (const row of rows) {
          for (const cell of row ?? []) {
            if (cell == null) continue;
            const text = String(cell).trim();
            if (text) values.push(text);
          }
        }
      }
      if (values.length === 0) {
        toast.error("No values found in that spreadsheet.");
        return;
      }
      setBulkText((prev) => (prev.trim() ? `${prev.trim()}\n${values.join("\n")}` : values.join("\n")));
      setFileName(file.name);
      toast.success(`Loaded ${values.length} cell values from ${file.name}`);

      const { data: auth } = await supabase.auth.getUser();
      if (auth.user) {
        await supabase.storage
          .from("bulk-uploads")
          .upload(`${auth.user.id}/${Date.now()}-${file.name}`, file, { upsert: false });
      }
    } catch {
      toast.error("Could not read that spreadsheet.");
    }
  }

  async function run() {
    if (busy) return;
    if (valid.length === 0) {
      toast.error("Enter at least one valid IP, domain or file hash.");
      return;
    }
    if (valid.length > MAX_BATCH) {
      toast.error(`Maximum ${MAX_BATCH} indicators per scan.`);
      return;
    }
    cancelRef.current = false;
    setCancelling(false);
    setBusy(true);
    setWarnings([]);
    setResults([]);
    setQueue(valid.map((v) => ({ value: v.value, type: v.type, status: "pending" as const })));

    const collected: DisplayResult[] = [];
    const warn = new Set<string>();
    let failed = false;

    try {
      for (let start = 0; start < valid.length; start += CHUNK_SIZE) {
        if (cancelRef.current) break;
        const chunk = valid.slice(start, start + CHUNK_SIZE);
        setQueue((prev) =>
          prev.map((item, i) =>
            i >= start && i < start + chunk.length ? { ...item, status: "scanning" } : item,
          ),
        );

        try {
          const res = await scan({ data: { indicators: chunk, mode } });
          const batch = res.results as DisplayResult[];
          collected.push(...batch);
          setResults([...collected]);
          setQueue((prev) =>
            prev.map((item, i) => {
              if (i < start || i >= start + chunk.length) return item;
              const match = batch[i - start];
              return match
                ? { ...item, status: match.error ? "error" : "done", verdict: match.verdict }
                : { ...item, status: "done" };
            }),
          );

          if (res.pools.virustotal.total === 0) warn.add("No VirusTotal API key configured.");
          else if (res.pools.virustotal.exhausted)
            warn.add("All VirusTotal keys have reached their daily limit.");
          if (res.pools.abuseipdb.total === 0 && counts.ip > 0)
            warn.add("No AbuseIPDB API key configured — IP abuse scores unavailable.");
          else if (res.pools.abuseipdb.exhausted)
            warn.add("All AbuseIPDB keys have reached their daily limit.");
          setWarnings([...warn]);
        } catch (e) {
          failed = true;
          setQueue((prev) =>
            prev.map((item, i) =>
              i >= start && i < start + chunk.length ? { ...item, status: "error" } : item,
            ),
          );
          toast.error((e as Error).message || "Scan failed.");
          break;
        }
      }

      if (cancelRef.current) {
        setQueue((prev) =>
          prev.map((item) => (item.status === "pending" ? { ...item, status: "cancelled" } : item)),
        );
        toast.info(`Scan cancelled — ${collected.length} of ${valid.length} completed.`);
      } else if (!failed) {
        const threats = collected.filter(
          (r) => r.verdict === "malicious" || r.verdict === "suspicious",
        ).length;
        toast.success(
          `Scanned ${collected.length} indicator${collected.length === 1 ? "" : "s"}${
            threats ? ` · ${threats} flagged` : ""
          }`,
        );
      }
    } finally {
      queryClient.invalidateQueries({ queryKey: ["api-keys"] });
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      setBusy(false);
      setCancelling(false);
      cancelRef.current = false;
    }
  }

  return (
    <AppShell>
      <PageHeader
        title="Checker"
        description="Look up IPs, domains and file hashes against VirusTotal and AbuseIPDB."
      />

      <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="panel p-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label className="text-[12px] text-muted-foreground">Indicator type</Label>
              <div className="flex flex-wrap gap-1.5">
                {TYPES.map((t) => (
                  <button
                    key={t.value}
                    type="button"
                    onClick={() => setType(t.value)}
                    className={cn(
                      "rounded-md border px-2.5 py-1.5 text-[12.5px] font-medium transition-colors duration-200",
                      type === t.value
                        ? "border-primary/40 bg-primary/12 text-primary"
                        : "border-border bg-secondary text-muted-foreground hover:text-foreground",
                    )}
                  >
                    {t.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-1.5">
              <Label className="text-[12px] text-muted-foreground">Scan mode</Label>
              <div className="flex gap-1.5">
                {(["single", "bulk"] as const).map((m) => (
                  <button
                    key={m}
                    type="button"
                    onClick={() => setMode(m)}
                    className={cn(
                      "flex-1 rounded-md border px-2.5 py-1.5 text-[12.5px] font-medium capitalize transition-colors duration-200",
                      mode === m
                        ? "border-primary/40 bg-primary/12 text-primary"
                        : "border-border bg-secondary text-muted-foreground hover:text-foreground",
                    )}
                  >
                    {m}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="mt-4">
            {mode === "single" ? (
              <div className="space-y-1.5">
                <Label htmlFor="indicator" className="text-[12px] text-muted-foreground">
                  Indicator
                </Label>
                <div className="flex flex-col gap-2 sm:flex-row">
                  <Input
                    id="indicator"
                    value={single}
                    onChange={(e) => setSingle(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") void run();
                    }}
                    placeholder="8.8.8.8 · example.com · 44d88612fea8a8f36de82e1278abb02f"
                    className="font-mono text-[13px]"
                    maxLength={255}
                  />
                  <Button onClick={run} disabled={busy} className="gap-1.5 sm:w-32">
                    {busy ? (
                      <Loader2 className="size-4 animate-spin" />
                    ) : (
                      <Search className="size-4" />
                    )}
                    Scan
                  </Button>
                </div>
              </div>
            ) : (
              <Tabs defaultValue="paste">
                <TabsList className="grid w-full grid-cols-2 sm:w-72">
                  <TabsTrigger value="paste">Paste list</TabsTrigger>
                  <TabsTrigger value="upload">Excel upload</TabsTrigger>
                </TabsList>

                <TabsContent value="paste" className="mt-3 space-y-2">
                  <Textarea
                    value={bulkText}
                    onChange={(e) => setBulkText(e.target.value)}
                    rows={9}
                    placeholder={"1.2.3.4\nmalicious-domain.com\n44d88612fea8a8f36de82e1278abb02f"}
                    className="resize-y font-mono text-[12.5px]"
                  />
                </TabsContent>

                <TabsContent value="upload" className="mt-3 space-y-2">
                  <div
                    onDragOver={(e) => e.preventDefault()}
                    onDrop={(e) => {
                      e.preventDefault();
                      const file = e.dataTransfer.files?.[0];
                      if (file) void handleFile(file);
                    }}
                    className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border bg-secondary/40 px-4 py-8 text-center transition-colors duration-200 hover:border-primary/40"
                  >
                    <FileSpreadsheet className="size-5 text-primary" />
                    <p className="mt-2 text-[13px] font-medium">Drop an .xlsx file</p>
                    <p className="mt-0.5 text-[11.5px] text-muted-foreground">
                      Every non-empty cell is parsed and auto-classified. Max 5 MB.
                    </p>
                    <input
                      ref={fileRef}
                      type="file"
                      accept=".xlsx"
                      className="hidden"
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        if (file) void handleFile(file);
                        e.target.value = "";
                      }}
                    />
                    <Button
                      variant="outline"
                      size="sm"
                      className="mt-3 gap-1.5"
                      onClick={() => fileRef.current?.click()}
                    >
                      <Upload className="size-3.5" /> Choose file
                    </Button>
                  </div>
                  {fileName && (
                    <div className="flex items-center gap-2 rounded-md border border-border bg-secondary px-2.5 py-1.5 text-[12px]">
                      <FileSpreadsheet className="size-3.5 text-primary" />
                      <span className="flex-1 truncate font-mono">{fileName}</span>
                      <button
                        type="button"
                        onClick={() => {
                          setFileName(null);
                          setBulkText("");
                        }}
                        className="text-muted-foreground transition-colors hover:text-foreground"
                        aria-label="Clear file"
                      >
                        <X className="size-3.5" />
                      </button>
                    </div>
                  )}
                  {bulkText && (
                    <Textarea
                      value={bulkText}
                      onChange={(e) => setBulkText(e.target.value)}
                      rows={6}
                      className="resize-y font-mono text-[12.5px]"
                    />
                  )}
                </TabsContent>

                <div className="mt-3">
                  <Button onClick={run} disabled={busy} className="w-full gap-1.5 sm:w-auto">
                    {busy ? <Loader2 className="size-4 animate-spin" /> : <Search className="size-4" />}
                    Scan {valid.length > 0 ? `${valid.length} indicators` : "batch"}
                  </Button>
                </div>
              </Tabs>
            )}
          </div>
        </div>

        <div className="panel h-fit p-4">
          <h2 className="text-sm font-semibold">Queue</h2>
          <p className="mt-1 text-[12px] text-muted-foreground">
            Detected before dispatch. Each provider call consumes one key from its pool.
          </p>
          <div className="mt-3 space-y-2">
            {(
              [
                ["IP addresses", counts.ip],
                ["Domains", counts.domain],
                ["File hashes", counts.hash],
              ] as const
            ).map(([label, count]) => (
              <div key={label} className="flex items-center justify-between text-[12.5px]">
                <span className="text-muted-foreground">{label}</span>
                <span className="font-mono">{count}</span>
              </div>
            ))}
            <div className="flex items-center justify-between border-t border-border pt-2 text-[12.5px] font-medium">
              <span>Total valid</span>
              <span className="font-mono">{valid.length}</span>
            </div>
            {invalid > 0 && (
              <div className="flex items-center justify-between text-[12.5px] text-warn">
                <span>Unrecognised</span>
                <span className="font-mono">{invalid}</span>
              </div>
            )}
          </div>
          {queue.length > 0 && (
            <div className="mt-4 border-t border-border pt-3">
              <div className="flex items-center justify-between text-[12.5px]">
                <span className="font-medium">
                  {busy ? "Scanning" : cancelledCount > 0 ? "Cancelled" : "Complete"}
                </span>
                <span className="font-mono text-muted-foreground">
                  {processedCount}/{queue.length}
                </span>
              </div>
              <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-secondary">
                <div
                  className="h-full rounded-full bg-primary transition-all duration-300 ease-out"
                  style={{ width: `${(processedCount / queue.length) * 100}%` }}
                />
              </div>
              <div className="mt-2.5 max-h-56 space-y-1 overflow-y-auto pr-1">
                {queue.map((item, i) => (
                  <div
                    key={`${item.value}-${i}`}
                    className="flex items-center gap-2 text-[11.5px]"
                    aria-live={item.status === "scanning" ? "polite" : undefined}
                  >
                    {item.status === "scanning" ? (
                      <Loader2 className="size-3 shrink-0 animate-spin text-primary" />
                    ) : item.status === "done" ? (
                      <CheckCircle2
                        className={cn(
                          "size-3 shrink-0",
                          item.verdict === "malicious"
                            ? "text-danger"
                            : item.verdict === "suspicious"
                              ? "text-warn"
                              : "text-safe",
                        )}
                      />
                    ) : item.status === "error" ? (
                      <AlertTriangle className="size-3 shrink-0 text-warn" />
                    ) : item.status === "cancelled" ? (
                      <X className="size-3 shrink-0 text-muted-foreground" />
                    ) : (
                      <Clock className="size-3 shrink-0 text-muted-foreground" />
                    )}
                    <span className="flex-1 truncate font-mono">{item.value}</span>
                    <span className="shrink-0 capitalize text-muted-foreground">{item.status}</span>
                  </div>
                ))}
              </div>
              {busy && (
                <Button
                  variant="outline"
                  size="sm"
                  className="mt-3 w-full gap-1.5 text-[12.5px]"
                  disabled={cancelling}
                  onClick={() => {
                    cancelRef.current = true;
                    setCancelling(true);
                  }}
                >
                  <X className="size-3.5" />
                  {cancelling ? "Cancelling…" : "Cancel scan"}
                </Button>
              )}
            </div>
          )}
          <div className="mt-3 flex flex-wrap gap-1.5">
            <Badge variant="outline" className="text-[10px]">
              VT: {counts.ip + counts.domain + counts.hash} calls
            </Badge>
            <Badge variant="outline" className="text-[10px]">
              AbuseIPDB: {counts.ip} calls
            </Badge>
          </div>
          <Button asChild variant="ghost" size="sm" className="mt-3 w-full text-[12.5px]">
            <Link to="/settings">Check quota</Link>
          </Button>
        </div>
      </div>

      {warnings.length > 0 && (
        <div className="mt-4 space-y-2">
          {warnings.map((w) => (
            <div
              key={w}
              className="flex items-center gap-2 rounded-lg border border-warn/30 bg-warn/10 px-3 py-2 text-[12.5px] text-warn"
            >
              <AlertTriangle className="size-3.5 shrink-0" />
              <span className="flex-1">{w}</span>
              <Link to="/settings" className="shrink-0 underline underline-offset-2">
                Manage keys
              </Link>
            </div>
          ))}
        </div>
      )}

      {results.length > 0 && (
        <div className="mt-5">
          <div className="mb-2.5 flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-3">
              <h2 className="text-sm font-semibold">Results</h2>
              <span className="inline-flex items-center gap-1.5 text-[11px] text-muted-foreground">
                <ShieldAlert className="size-3.5 text-danger" />
                {results.filter((r) => r.verdict === "malicious").length} malicious ·{" "}
                {results.filter((r) => r.verdict === "suspicious").length} suspicious
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1.5 text-[12px]"
                onClick={() => {
                  exportResultsCsv(filteredResults);
                  toast.success("CSV exported");
                }}
              >
                <Download className="size-3.5" /> CSV
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1.5 text-[12px]"
                onClick={async () => {
                  try {
                    await exportResultsXlsx(filteredResults);
                    toast.success("Excel exported");
                  } catch {
                    toast.error("Could not build the Excel file.");
                  }
                }}
              >
                <FileSpreadsheet className="size-3.5" /> Excel
              </Button>
            </div>
          </div>

          <div className="panel mb-2.5 flex flex-col gap-2 p-2.5 sm:flex-row sm:items-center">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search results by indicator, ISP, country, registrar…"
                className="h-8 pl-8 font-mono text-[12px]"
                aria-label="Search results"
              />
              {query && (
                <button
                  type="button"
                  onClick={() => setQuery("")}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground transition-colors hover:text-foreground"
                  aria-label="Clear search"
                >
                  <X className="size-3.5" />
                </button>
              )}
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              {VERDICT_FILTERS.map((f) => (
                <button
                  key={f.value}
                  type="button"
                  onClick={() => setVerdictFilter(f.value)}
                  className={cn(
                    "rounded-md border px-2 py-1 text-[11.5px] font-medium transition-colors duration-200",
                    verdictFilter === f.value
                      ? "border-primary/40 bg-primary/12 text-primary"
                      : "border-border bg-secondary text-muted-foreground hover:text-foreground",
                  )}
                >
                  {f.label}
                </button>
              ))}
              <span className="ml-1 text-[11px] text-muted-foreground">
                {filteredResults.length}/{results.length}
              </span>
            </div>
          </div>

          {filteredResults.length === 0 ? (
            <div className="panel px-4 py-8 text-center text-[12.5px] text-muted-foreground">
              No results match your search or filter.
            </div>
          ) : (
            <div className="space-y-2">
              {filteredResults.map((r, i) => (
                <ResultCard key={`${r.indicator}-${i}`} result={r} index={i} />
              ))}
            </div>
          )}
        </div>
      )}
    </AppShell>
  );
}
