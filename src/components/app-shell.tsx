import { useEffect, useState } from "react";
import { Link, useRouter, useRouterState } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { LayoutDashboard, ScanSearch, Settings, ShieldCheck, LogOut, Menu } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { SiteFooter } from "@/components/site-footer";

const NAV = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/checker", label: "Checker", icon: ScanSearch },
  { to: "/settings", label: "Settings", icon: Settings },
] as const;

export function AppShell({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const [email, setEmail] = useState<string | null>(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    supabase.auth.getUser().then(({ data }) => setEmail(data.user?.email ?? null));
  }, []);

  useEffect(() => setOpen(false), [pathname]);

  async function signOut() {
    await queryClient.cancelQueries();
    queryClient.clear();
    await supabase.auth.signOut();
    router.navigate({ to: "/auth", replace: true });
  }

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <header className="sticky top-0 z-40 border-b border-border bg-background/85 backdrop-blur supports-[backdrop-filter]:bg-background/70">
        <div className="mx-auto flex h-14 max-w-7xl items-center gap-3 px-3 sm:px-5">
          <Link to="/dashboard" className="flex shrink-0 items-center gap-2">
            <span className="grid size-7 place-items-center rounded-md bg-primary/15 text-primary ring-1 ring-primary/25">
              <ShieldCheck className="size-4" />
            </span>
            <span className="font-display text-sm font-bold tracking-tight">IP-GUARD</span>
          </Link>

          <nav className="ml-2 hidden items-center gap-1 sm:flex">
            {NAV.map((item) => {
              const active = pathname.startsWith(item.to);
              return (
                <Link
                  key={item.to}
                  to={item.to}
                  className={cn(
                    "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-[13px] font-medium transition-colors duration-200",
                    active
                      ? "bg-primary/12 text-primary"
                      : "text-muted-foreground hover:bg-accent hover:text-foreground",
                  )}
                >
                  <item.icon className="size-3.5" />
                  {item.label}
                </Link>
              );
            })}
          </nav>

          <div className="ml-auto flex items-center gap-2">
            <span className="hidden max-w-[180px] truncate font-mono text-[11px] text-muted-foreground md:inline">
              {email}
            </span>
            <Button
              variant="ghost"
              size="sm"
              onClick={signOut}
              className="h-8 gap-1.5 px-2 text-[13px] text-muted-foreground hover:text-foreground"
            >
              <LogOut className="size-3.5" />
              <span className="hidden sm:inline">Sign out</span>
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="size-8 sm:hidden"
              aria-label="Toggle navigation"
              onClick={() => setOpen((v) => !v)}
            >
              <Menu className="size-4" />
            </Button>
          </div>
        </div>

        {open && (
          <nav className="grid gap-1 border-t border-border px-3 py-2 sm:hidden">
            {NAV.map((item) => (
              <Link
                key={item.to}
                to={item.to}
                className={cn(
                  "inline-flex items-center gap-2 rounded-md px-2.5 py-2 text-sm font-medium transition-colors",
                  pathname.startsWith(item.to)
                    ? "bg-primary/12 text-primary"
                    : "text-muted-foreground hover:bg-accent hover:text-foreground",
                )}
              >
                <item.icon className="size-4" />
                {item.label}
              </Link>
            ))}
          </nav>
        )}
      </header>

      <main className="mx-auto w-full max-w-7xl flex-1 px-3 py-5 sm:px-5 sm:py-6">{children}</main>

      <SiteFooter />
    </div>
  );
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight sm:text-2xl">{title}</h1>
        {description && (
          <p className="mt-1 text-[13px] text-muted-foreground">{description}</p>
        )}
      </div>
      {actions}
    </div>
  );
}
