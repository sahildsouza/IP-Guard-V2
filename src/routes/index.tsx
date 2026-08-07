import { Link, createFileRoute } from "@tanstack/react-router";
import { SiteFooter } from "@/components/site-footer";
import { useEffect, useState } from "react";
import { ShieldCheck, Globe, Fingerprint, Network, ArrowRight, KeyRound } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "IP-Guard — VirusTotal & AbuseIPDB Threat Console" },
      {
        name: "description",
        content:
          "Scan IPs, domains and file hashes in bulk against VirusTotal and AbuseIPDB with rotating API keys and daily quota tracking.",
      },
      { property: "og:title", content: "IP-Guard — VirusTotal & AbuseIPDB Threat Console" },
      {
        property: "og:description",
        content:
          "Single and bulk indicator scanning with round-robin API key rotation and IST quota resets.",
      },
    ],
  }),
  component: Landing,
});

const FEATURES = [
  {
    icon: Network,
    title: "IP reputation",
    body: "Abuse confidence, ISP, country, usage type and VirusTotal engine detections.",
  },
  {
    icon: Globe,
    title: "Domain intel",
    body: "Reputation, categories, registrar, creation date and last analysis stats.",
  },
  {
    icon: Fingerprint,
    title: "File hashes",
    body: "Detection ratio, threat labels, file type, first seen and last analysis.",
  },
  {
    icon: KeyRound,
    title: "Key rotation",
    body: "Round-robin across key pools, skipping any key that hit its daily cap.",
  },
];

function Landing() {
  const [signedIn, setSignedIn] = useState(false);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => setSignedIn(!!data.session));
  }, []);

  return (
    <div className="relative flex min-h-screen flex-col overflow-hidden">
      <div className="grid-backdrop pointer-events-none absolute inset-0 opacity-35" />
      <div className="pointer-events-none absolute inset-x-0 top-0 h-96 bg-[radial-gradient(55%_100%_at_50%_0%,color-mix(in_oklab,var(--primary)_18%,transparent),transparent)]" />

      <div className="relative mx-auto max-w-5xl px-4 py-16 sm:py-24">
        <div className="animate-rise flex flex-col items-center text-center">
          <span className="inline-flex items-center gap-2 rounded-full border border-border bg-card px-3 py-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            <ShieldCheck className="size-3.5 text-primary" />
            VirusTotal · AbuseIPDB
          </span>
          <h1 className="mt-5 max-w-2xl text-3xl font-bold tracking-tight sm:text-5xl">
            Threat intelligence lookups, without the quota headaches
          </h1>
          <p className="mt-4 max-w-xl text-sm text-muted-foreground sm:text-[15px]">
            Scan IPs, domains and file hashes one at a time or in bulk. IP-Guard rotates
            across your API key pools, tracks every request and resets quotas at midnight
            IST.
          </p>
          <div className="mt-7 flex flex-wrap items-center justify-center gap-2">
            <Button asChild size="lg" className="gap-2">
              <Link to={signedIn ? "/dashboard" : "/auth"}>
                {signedIn ? "Open dashboard" : "Get started"}
                <ArrowRight className="size-4" />
              </Link>
            </Button>
            <Button asChild size="lg" variant="outline">
              <Link to={signedIn ? "/checker" : "/auth"}>Run a scan</Link>
            </Button>
          </div>
        </div>

        <div className="mt-14 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {FEATURES.map((f) => (
            <div
              key={f.title}
              className="panel p-4 transition-colors duration-200 hover:border-primary/40"
            >
              <f.icon className="size-4 text-primary" />
              <h2 className="mt-3 text-sm font-semibold">{f.title}</h2>
              <p className="mt-1.5 text-[13px] leading-relaxed text-muted-foreground">
                {f.body}
              </p>
            </div>
          ))}
        </div>
      </div>

      <SiteFooter className="relative" />
    </div>
  );
}
