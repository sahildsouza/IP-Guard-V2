import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";

export type ApiKeyRow = {
  id: string;
  service: "virustotal" | "abuseipdb";
  label: string;
  api_key: string;
  daily_limit: number;
  requests_used: number;
  last_reset_date: string;
  is_active: boolean;
  last_used_at: string | null;
  created_at: string;
};

export type ScanRow = {
  id: string;
  indicator: string;
  indicator_type: "ip" | "domain" | "hash";
  scan_mode: string;
  verdict: string;
  malicious_count: number;
  suspicious_count: number;
  harmless_count: number;
  abuse_score: number | null;
  reputation: number | null;
  summary: Record<string, unknown>;
  error: string | null;
  created_at: string;
};

export function useApiKeys() {
  return useQuery({
    queryKey: ["api-keys"],
    queryFn: async (): Promise<ApiKeyRow[]> => {
      const { data, error } = await supabase
        .from("api_keys")
        .select("*")
        .order("service")
        .order("created_at");
      if (error) throw error;
      return (data ?? []) as ApiKeyRow[];
    },
  });
}

export function useScans(limit = 200) {
  return useQuery({
    queryKey: ["scans", limit],
    queryFn: async (): Promise<ScanRow[]> => {
      const { data, error } = await supabase
        .from("scans")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(limit);
      if (error) throw error;
      return (data ?? []) as unknown as ScanRow[];
    },
  });
}

export function useProfile() {
  return useQuery({
    queryKey: ["profile"],
    queryFn: async () => {
      const { data: auth } = await supabase.auth.getUser();
      if (!auth.user) return null;
      const { data } = await supabase
        .from("profiles")
        .select("*")
        .eq("id", auth.user.id)
        .maybeSingle();
      return {
        id: auth.user.id,
        email: auth.user.email ?? null,
        display_name: data?.display_name ?? null,
        created_at: data?.created_at ?? auth.user.created_at,
      };
    },
  });
}
