"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Activity, LayoutDashboard, Settings2, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";

const navigation = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/scans", label: "Scans", icon: ShieldCheck },
  { href: "/settings", label: "Settings", icon: Settings2 },
] as const;

export function SidebarNavigation({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname();

  return (
    <nav aria-label="Primary navigation" className="space-y-1">
      {navigation.map(({ href, label, icon: Icon }) => {
        const active = pathname === href || pathname.startsWith(`${href}/`);
        return (
          <Link
            key={href}
            aria-current={active ? "page" : undefined}
            className={cn(
              "group flex min-h-10 items-center gap-3 rounded-lg px-3 text-[13px] font-medium transition-colors",
              "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-sidebar",
              active ? "bg-primary/10 text-foreground shadow-[inset_2px_0_0_var(--primary)]" : "text-muted-foreground hover:bg-sidebar-accent hover:text-foreground",
            )}
            href={href}
            onClick={onNavigate}
          >
            <Icon aria-hidden="true" className={cn("size-[17px]", active ? "text-primary" : "text-muted-foreground group-hover:text-foreground")} strokeWidth={1.8} />
            {label}
            {active && <span className="sr-only">Current page</span>}
          </Link>
        );
      })}
    </nav>
  );
}

export function SidebarFooter() {
  return (
    <div className="space-y-3">
      <div className="rounded-xl border border-border/70 bg-background/55 p-3.5">
        <div className="flex items-center gap-2 text-xs font-medium text-foreground">
          <span className="grid size-7 place-items-center rounded-lg bg-primary/10 text-primary">
            <Activity aria-hidden="true" className="size-3.5" />
          </span>
          Personal workspace
        </div>
        <p className="mt-2 text-[11px] leading-5 text-muted-foreground">Your authorized assessments, together in one place.</p>
      </div>
      <p className="px-1 text-[10px] tracking-wide text-muted-foreground/75">WEBGUARD PREVIEW <span aria-hidden="true">·</span> V0.3</p>
    </div>
  );
}
