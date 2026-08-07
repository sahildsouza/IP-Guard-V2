import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  KeyRound,
  Loader2,
  Plus,
  Trash2,
  Power,
  Clock,
  Mail,
  User as UserIcon,
} from "lucide-react";
import { AppShell, PageHeader } from "@/components/app-shell";
import { UsageBar, SERVICE_META, effectiveUsed } from "@/components/usage";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { supabase } from "@/integrations/supabase/client";
import { useApiKeys, useProfile, type ApiKeyRow } from "@/hooks/use-app-data";
import { formatCountdown, istResetLabel, msUntilIstReset } from "@/lib/indicators";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/_authenticated/settings")({
  head: () => ({
    meta: [
      { title: "Settings — API Keys & Quota" },
      {
        name: "description",
        content:
          "Manage VirusTotal and AbuseIPDB API keys, review per-key daily usage and next IST reset time.",
      },
      { property: "og:title", content: "Settings — API Keys & Quota" },
      {
        property: "og:description",
        content: "Add, disable or remove keys and track per-key request consumption.",
      },
    ],
  }),
  component: Settings,
});

const SERVICES = ["virustotal", "abuseipdb"] as const;
type Service = (typeof SERVICES)[number];

function Settings() {
  const keys = useApiKeys();
  const profile = useProfile();
  const queryClient = useQueryClient();

  const [service, setService] = useState<Service>("virustotal");
  const [label, setLabel] = useState("");
  const [apiKey, setApiKey] = useState("");

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["api-keys"] });

  const addKey = useMutation({
    mutationFn: async () => {
      const trimmed = apiKey.trim();
      if (trimmed.length < 20) throw new Error("That key looks too short.");
      const { data: auth } = await supabase.auth.getUser();
      if (!auth.user) throw new Error("You are not signed in.");
      const { error } = await supabase.from("api_keys").insert({
        user_id: auth.user.id,
        service,
        label: label.trim().slice(0, 60) || `${SERVICE_META[service].name} key`,
        api_key: trimmed,
        daily_limit: SERVICE_META[service].limit,
      });
      if (error) throw error;
    },
    onSuccess: () => {
      setLabel("");
      setApiKey("");
      toast.success("API key added.");
      invalidate();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const toggleKey = useMutation({
    mutationFn: async (row: ApiKeyRow) => {
      const { error } = await supabase
        .from("api_keys")
        .update({ is_active: !row.is_active })
        .eq("id", row.id);
      if (error) throw error;
    },
    onSuccess: () => {
      toast.success("Key updated.");
      invalidate();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const removeKey = useMutation({
    mutationFn: async (row: ApiKeyRow) => {
      const { error } = await supabase.from("api_keys").delete().eq("id", row.id);
      if (error) throw error;
    },
    onSuccess: () => {
      toast.success("Key removed.");
      invalidate();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const grouped = useMemo(() => {
    const rows = keys.data ?? [];
    return SERVICES.map((s) => {
      const pool = rows.filter((k) => k.service === s);
      return {
        service: s,
        pool,
        used: pool.reduce((n, k) => n + effectiveUsed(k), 0),
        limit: pool.reduce((n, k) => n + (k.is_active ? k.daily_limit : 0), 0),
      };
    });
  }, [keys.data]);

  return (
    <AppShell>
      <PageHeader
        title="Settings"
        description="Account details, API key pools and per-key daily consumption."
      />

      <div className="grid gap-3 lg:grid-cols-[320px_minmax(0,1fr)]">
        <div className="space-y-3">
          <div className="panel p-4">
            <h2 className="text-sm font-semibold">Account</h2>
            {profile.isLoading ? (
              <Skeleton className="mt-3 h-16 w-full" />
            ) : (
              <div className="mt-3 space-y-2.5 text-[12.5px]">
                <div className="flex items-center gap-2">
                  <UserIcon className="size-3.5 text-muted-foreground" />
                  <span className="text-muted-foreground">Name</span>
                  <span className="ml-auto truncate font-medium">
                    {profile.data?.display_name || "—"}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <Mail className="size-3.5 text-muted-foreground" />
                  <span className="text-muted-foreground">Email</span>
                  <span className="ml-auto truncate font-mono text-[11.5px]">
                    {profile.data?.email}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <Clock className="size-3.5 text-muted-foreground" />
                  <span className="text-muted-foreground">Quota reset</span>
                  <span className="ml-auto font-mono text-[11.5px]">
                    {istResetLabel()} · in {formatCountdown(msUntilIstReset())}
                  </span>
                </div>
              </div>
            )}
          </div>

          <div className="panel p-4">
            <h2 className="flex items-center gap-1.5 text-sm font-semibold">
              <Plus className="size-3.5" /> Add API key
            </h2>
            <div className="mt-3 space-y-3">
              <div className="space-y-1.5">
                <Label className="text-[12px] text-muted-foreground">Service</Label>
                <div className="flex gap-1.5">
                  {SERVICES.map((s) => (
                    <button
                      key={s}
                      type="button"
                      onClick={() => setService(s)}
                      className={cn(
                        "flex-1 rounded-md border px-2 py-1.5 text-[12px] font-medium transition-colors duration-200",
                        service === s
                          ? "border-primary/40 bg-primary/12 text-primary"
                          : "border-border bg-secondary text-muted-foreground hover:text-foreground",
                      )}
                    >
                      {SERVICE_META[s].name}
                    </button>
                  ))}
                </div>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="label" className="text-[12px] text-muted-foreground">
                  Label
                </Label>
                <Input
                  id="label"
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  placeholder="Primary key"
                  maxLength={60}
                  className="text-[13px]"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="apikey" className="text-[12px] text-muted-foreground">
                  API key
                </Label>
                <Input
                  id="apikey"
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder="Paste key"
                  maxLength={200}
                  className="font-mono text-[12.5px]"
                />
              </div>
              <p className="text-[11px] text-muted-foreground">
                Daily limit applied automatically: {SERVICE_META[service].limit.toLocaleString()}{" "}
                requests per key.
              </p>
              <Button
                onClick={() => addKey.mutate()}
                disabled={addKey.isPending || apiKey.trim().length === 0}
                size="sm"
                className="w-full gap-1.5"
              >
                {addKey.isPending ? (
                  <Loader2 className="size-3.5 animate-spin" />
                ) : (
                  <KeyRound className="size-3.5" />
                )}
                Add key
              </Button>
            </div>
          </div>
        </div>

        <div className="space-y-3">
          {grouped.map((group) => {
            const meta = SERVICE_META[group.service];
            return (
              <div key={group.service} className="panel p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h2 className="text-sm font-semibold">{meta.name}</h2>
                    <p className="mt-0.5 text-[11.5px] text-muted-foreground">
                      {meta.limit.toLocaleString()} requests/day per key · round-robin rotation
                    </p>
                  </div>
                  <Badge variant="outline" className="font-mono text-[10.5px]">
                    {group.used.toLocaleString()} / {group.limit.toLocaleString()} today
                  </Badge>
                </div>

                <div className="mt-3">
                  <UsageBar used={group.used} limit={group.limit} barClassName={meta.bar} />
                </div>

                <div className="mt-4 space-y-2">
                  {keys.isLoading ? (
                    <Skeleton className="h-16 w-full" />
                  ) : group.pool.length === 0 ? (
                    <p className="rounded-md border border-dashed border-border px-3 py-5 text-center text-[12.5px] text-muted-foreground">
                      No {meta.name} keys yet.
                    </p>
                  ) : (
                    group.pool.map((row) => {
                      const used = effectiveUsed(row);
                      const exhausted = used >= row.daily_limit;
                      return (
                        <div
                          key={row.id}
                          className="rounded-lg border border-border bg-secondary/40 p-3 transition-colors duration-200 hover:border-primary/25"
                        >
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="truncate text-[13px] font-medium">{row.label}</span>
                            <span className="font-mono text-[11px] text-muted-foreground">
                              ••••{row.api_key.slice(-4)}
                            </span>
                            {!row.is_active ? (
                              <Badge variant="outline" className="text-[10px] text-muted-foreground">
                                Disabled
                              </Badge>
                            ) : exhausted ? (
                              <Badge variant="outline" className="border-warn/40 text-[10px] text-warn">
                                Limit reached
                              </Badge>
                            ) : (
                              <Badge variant="outline" className="border-safe/40 text-[10px] text-safe">
                                Active
                              </Badge>
                            )}
                            <div className="ml-auto flex items-center gap-1">
                              <Button
                                variant="ghost"
                                size="icon"
                                className="size-7"
                                title={row.is_active ? "Disable key" : "Enable key"}
                                onClick={() => toggleKey.mutate(row)}
                              >
                                <Power className="size-3.5" />
                              </Button>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="size-7 text-danger hover:text-danger"
                                title="Remove key"
                                onClick={() => removeKey.mutate(row)}
                              >
                                <Trash2 className="size-3.5" />
                              </Button>
                            </div>
                          </div>
                          <div className="mt-2.5">
                            <div className="mb-1 flex items-center justify-between text-[11px] text-muted-foreground">
                              <span>
                                {used.toLocaleString()} / {row.daily_limit.toLocaleString()} used
                              </span>
                              <span className="font-mono">
                                resets in {formatCountdown(msUntilIstReset())}
                              </span>
                            </div>
                            <UsageBar used={used} limit={row.daily_limit} barClassName={meta.bar} />
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </AppShell>
  );
}
