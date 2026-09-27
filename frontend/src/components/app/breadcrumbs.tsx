"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ChevronRight, Home } from "lucide-react";

const labels: Record<string, string> = {
  dashboard: "Dashboard",
  scans: "Scans",
  settings: "Settings",
};

export function Breadcrumbs() {
  const pathname = usePathname();
  const isScanDetail = pathname.startsWith("/scans/");
  const parts = isScanDetail
    ? [{ label: "Scans", href: "/scans" }, { label: "Report" }]
    : [{ label: labels[pathname.slice(1)] ?? "Workspace" }];

  return (
    <nav aria-label="Breadcrumb" className="min-w-0">
      <ol className="flex items-center gap-1.5 text-xs">
        <li>
          <Link aria-label="Dashboard" className="rounded-sm text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" href="/dashboard">
            <Home aria-hidden="true" className="size-3.5" />
          </Link>
        </li>
        {parts.map((part, index) => (
          <li className="flex min-w-0 items-center gap-1.5" key={`${part.label}-${index}`}>
            <ChevronRight aria-hidden="true" className="size-3 shrink-0 text-muted-foreground/70" />
            {part.href ? (
              <Link className="rounded-sm text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" href={part.href}>{part.label}</Link>
            ) : (
              <span aria-current="page" className="truncate font-medium text-foreground">{part.label}</span>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
}
