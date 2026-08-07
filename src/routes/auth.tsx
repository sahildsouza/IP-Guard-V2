import { useEffect, useState } from "react";
import { createFileRoute, useNavigate, useSearch } from "@tanstack/react-router";
import { z } from "zod";
import { toast } from "sonner";
import { SiteFooter } from "@/components/site-footer";
import { ShieldCheck, Loader2 } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";

const schema = z.object({
  email: z.string().trim().email("Enter a valid email").max(255),
  password: z.string().min(8, "Password must be at least 8 characters").max(72),
});

export const Route = createFileRoute("/auth")({
  validateSearch: z.object({ redirect: z.string().optional() }),
  head: () => ({
    meta: [
      { title: "Sign in — IP-Guard Threat Console" },
      {
        name: "description",
        content:
          "Sign in to IP-Guard to scan IPs, domains and file hashes with VirusTotal and AbuseIPDB.",
      },
      { property: "og:title", content: "Sign in — IP-Guard Threat Console" },
      {
        property: "og:description",
        content: "Access your threat intelligence console and API key pools.",
      },
    ],
  }),
  component: AuthPage,
});

function AuthPage() {
  const navigate = useNavigate();
  const search = useSearch({ from: "/auth" });
  const dest = search.redirect?.startsWith("/") ? search.redirect : "/dashboard";
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      if (data.session) navigate({ to: dest, replace: true });
    });
  }, [navigate, dest]);

  async function signIn(e: React.FormEvent) {
    e.preventDefault();
    const parsed = schema.safeParse({ email, password });
    if (!parsed.success) {
      toast.error(parsed.error.issues[0]!.message);
      return;
    }
    setBusy(true);
    const { error } = await supabase.auth.signInWithPassword(parsed.data);
    setBusy(false);
    if (error) {
      toast.error(error.message);
      return;
    }
    navigate({ to: dest, replace: true });
  }

  async function signUp(e: React.FormEvent) {
    e.preventDefault();
    const parsed = schema.safeParse({ email, password });
    if (!parsed.success) {
      toast.error(parsed.error.issues[0]!.message);
      return;
    }
    setBusy(true);
    const { data, error } = await supabase.auth.signUp({
      ...parsed.data,
      options: {
        emailRedirectTo: window.location.origin,
        data: { display_name: name.trim() || undefined },
      },
    });
    setBusy(false);
    if (error) {
      toast.error(error.message);
      return;
    }
    if (data.session) {
      navigate({ to: dest, replace: true });
      return;
    }
    setSent(true);
    toast.success("Check your email to confirm your account.");
  }

  async function google() {
    setBusy(true);
    const { error } = await supabase.auth.signInWithOAuth({
      provider: "google",
      options: { redirectTo: window.location.origin },
    });
    if (error) {
      setBusy(false);
      toast.error("Google sign-in failed. Please try again.");
    }
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center px-4 py-10 pb-20">
      <div className="grid-backdrop pointer-events-none absolute inset-0 opacity-40" />
      <div className="pointer-events-none absolute inset-x-0 top-0 h-72 bg-[radial-gradient(60%_100%_at_50%_0%,color-mix(in_oklab,var(--primary)_16%,transparent),transparent)]" />

      <div className="animate-rise relative w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center text-center">
          <span className="grid size-10 place-items-center rounded-lg bg-primary/15 text-primary ring-1 ring-primary/25">
            <ShieldCheck className="size-5" />
          </span>
          <h1 className="mt-3 font-display text-lg font-bold tracking-tight">IP-GUARD</h1>
          <p className="mt-1 text-[13px] text-muted-foreground">
            Threat intelligence console for IPs, domains and hashes.
          </p>
        </div>

        <div className="panel p-4 shadow-2xl shadow-black/30">
          {sent ? (
            <div className="py-6 text-center">
              <p className="text-sm font-medium">Confirm your email</p>
              <p className="mt-2 text-[13px] text-muted-foreground">
                We sent a confirmation link to <span className="font-mono">{email}</span>.
              </p>
            </div>
          ) : (
            <Tabs defaultValue="signin">
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="signin">Sign in</TabsTrigger>
                <TabsTrigger value="signup">Create account</TabsTrigger>
              </TabsList>

              <TabsContent value="signin" className="mt-4">
                <form onSubmit={signIn} className="space-y-3">
                  <Field id="si-email" label="Email">
                    <Input
                      id="si-email"
                      type="email"
                      autoComplete="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="analyst@company.com"
                    />
                  </Field>
                  <Field id="si-pw" label="Password">
                    <Input
                      id="si-pw"
                      type="password"
                      autoComplete="current-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="••••••••"
                    />
                  </Field>
                  <Button type="submit" disabled={busy} className="w-full">
                    {busy && <Loader2 className="mr-2 size-4 animate-spin" />}
                    Sign in
                  </Button>
                </form>
              </TabsContent>

              <TabsContent value="signup" className="mt-4">
                <form onSubmit={signUp} className="space-y-3">
                  <Field id="su-name" label="Display name">
                    <Input
                      id="su-name"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="Alex Mercer"
                      maxLength={80}
                    />
                  </Field>
                  <Field id="su-email" label="Email">
                    <Input
                      id="su-email"
                      type="email"
                      autoComplete="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="analyst@company.com"
                    />
                  </Field>
                  <Field id="su-pw" label="Password">
                    <Input
                      id="su-pw"
                      type="password"
                      autoComplete="new-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="At least 8 characters"
                    />
                  </Field>
                  <Button type="submit" disabled={busy} className="w-full">
                    {busy && <Loader2 className="mr-2 size-4 animate-spin" />}
                    Create account
                  </Button>
                </form>
              </TabsContent>
            </Tabs>
          )}

          {!sent && (
            <>
              <div className="my-4 flex items-center gap-3">
                <span className="h-px flex-1 bg-border" />
                <span className="text-[11px] uppercase tracking-wider text-muted-foreground">
                  or
                </span>
                <span className="h-px flex-1 bg-border" />
              </div>
              <Button
                variant="outline"
                className="w-full gap-2"
                disabled={busy}
                onClick={google}
              >
                <GoogleIcon />
                Continue with Google
              </Button>
            </>
          )}
        </div>
      </div>
      <SiteFooter className="absolute inset-x-0 bottom-0 border-0 bg-transparent" />
    </div>
  );
}

function Field({
  id,
  label,
  children,
}: {
  id: string;
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id} className="text-[12px] text-muted-foreground">
        {label}
      </Label>
      {children}
    </div>
  );
}

function GoogleIcon() {
  return (
    <svg viewBox="0 0 24 24" className="size-4" aria-hidden>
      <path
        fill="#4285F4"
        d="M23.5 12.3c0-.9-.1-1.5-.2-2.2H12v4.2h6.5c-.1 1.1-.8 2.7-2.4 3.8v3.1h3.9c2.3-2.2 3.5-5.3 3.5-8.9z"
      />
      <path
        fill="#34A853"
        d="M12 24c3.2 0 5.9-1.1 7.9-2.9l-3.9-3.1c-1 .7-2.4 1.2-4 1.2-3.1 0-5.7-2-6.6-4.8H1.4v3.2C3.4 21.4 7.4 24 12 24z"
      />
      <path fill="#FBBC05" d="M5.4 14.4a7.2 7.2 0 0 1 0-4.6V6.6H1.4a12 12 0 0 0 0 10.8l4-3z" />
      <path
        fill="#EA4335"
        d="M12 4.8c1.8 0 3.3.6 4.5 1.8l3.4-3.4C17.9 1.2 15.2 0 12 0 7.4 0 3.4 2.6 1.4 6.6l4 3.2C6.3 6.9 8.9 4.8 12 4.8z"
      />
    </svg>
  );
}
