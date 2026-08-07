import { Github, Linkedin } from "lucide-react";

const LINKS = [
  {
    label: "LinkedIn",
    href: "https://in.linkedin.com/in/sahildsouza-work",
    icon: Linkedin,
  },
  {
    label: "GitHub",
    href: "https://github.com/sahildsouza",
    icon: Github,
  },
] as const;

export function SiteFooter({ className }: { className?: string }) {
  return (
    <footer
      className={
        "mt-auto border-t border-border bg-background/60" + (className ? ` ${className}` : "")
      }
    >
      <div className="mx-auto flex w-full max-w-7xl flex-col items-center justify-between gap-2 px-3 py-4 sm:flex-row sm:px-5">
        <p className="text-[12px] text-muted-foreground">
          Created by <span className="font-medium text-foreground">Sahil D&apos;Souza</span>
        </p>
        <div className="flex items-center gap-1.5">
          {LINKS.map((link) => (
            <a
              key={link.label}
              href={link.href}
              target="_blank"
              rel="noreferrer noopener"
              aria-label={link.label}
              className="inline-flex items-center gap-1.5 rounded-md border border-border bg-secondary px-2 py-1 text-[11.5px] font-medium text-muted-foreground transition-colors duration-200 hover:border-primary/40 hover:text-primary"
            >
              <link.icon className="size-3.5" />
              {link.label}
            </a>
          ))}
        </div>
      </div>
    </footer>
  );
}
