import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import {
  KeyPool,
  flushUsage,
  scanOne,
  istDateString,
  type KeyRow,
  type ScanResult,
} from "./scan.server";

const scanInput = z.object({
  indicators: z
    .array(
      z.object({
        value: z.string().trim().min(1).max(255),
        type: z.enum(["ip", "domain", "hash"]),
      }),
    )
    .min(1)
    .max(200),
  mode: z.enum(["single", "bulk"]).default("single"),
});

export const runScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) => scanInput.parse(input))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;

    const { data: keys, error } = await supabase
      .from("api_keys")
      .select("id, service, label, api_key, daily_limit, requests_used, last_reset_date, is_active")
      .order("created_at", { ascending: true });
    if (error) throw new Error(error.message);

    const rows = (keys ?? []) as KeyRow[];
    const vt = new KeyPool(rows.filter((k) => k.service === "virustotal"));
    const abuse = new KeyPool(rows.filter((k) => k.service === "abuseipdb"));

    const results: ScanResult[] = [];
    for (const item of data.indicators) {
      try {
        results.push(await scanOne(item.value, item.type, { vt, abuse }));
      } catch (e) {
        results.push({
          indicator: item.value,
          indicator_type: item.type,
          verdict: "unknown",
          malicious_count: 0,
          suspicious_count: 0,
          harmless_count: 0,
          undetected_count: 0,
          abuse_score: null,
          reputation: null,
          summary: {},
          error: (e as Error).message,
          vt_raw: null,
          abuse_raw: null,
          calls: [],
        });
      }
    }

    await flushUsage(supabase, [vt, abuse]);

    await supabase.from("scans").insert(
      results.map((r) => ({
        user_id: userId,
        indicator: r.indicator,
        indicator_type: r.indicator_type,
        scan_mode: data.mode,
        verdict: r.verdict,
        malicious_count: r.malicious_count,
        suspicious_count: r.suspicious_count,
        harmless_count: r.harmless_count,
        abuse_score: r.abuse_score,
        reputation: r.reputation,
        summary: { ...r.summary, calls: r.calls },
        vt_raw: r.vt_raw,
        abuse_raw: r.abuse_raw,
        error: r.error,
      })),
    );

    return {
      results,
      pools: {
        virustotal: { total: vt.size, exhausted: vt.size > 0 && vt.take() === null },
        abuseipdb: { total: abuse.size, exhausted: abuse.size > 0 && abuse.take() === null },
      },
    };
  });

export const resetStaleUsage = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const today = istDateString();
    const { error } = await context.supabase
      .from("api_keys")
      .update({ requests_used: 0, last_reset_date: today })
      .lt("last_reset_date", today);
    if (error) throw new Error(error.message);
    return { ok: true, ist_date: today };
  });
