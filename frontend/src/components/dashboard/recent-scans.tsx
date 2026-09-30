import Link from "next/link";
import { ArrowRight, Clock3 } from "lucide-react";
import { EmptyState } from "@/components/shared/empty-state";
import { ScanStatusBadge } from "@/components/shared/scan-status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ScanSummary } from "@/lib/scanner/types";

export function RecentScans({ scans }: { scans: ScanSummary[] }) {
  return (
    <Card className="min-w-0 border-border/70 bg-card/80 shadow-none">
      <CardHeader className="flex-row items-center justify-between gap-3 border-b border-border/60 pb-4">
        <div>
          <p className="text-[10px] font-semibold tracking-[0.16em] text-muted-foreground uppercase">Activity</p>
          <CardTitle className="mt-1.5 text-base">Recent scans</CardTitle>
        </div>
        <Button render={<Link href="/scans" />} size="sm" variant="ghost">
          Scan history <ArrowRight aria-hidden="true" className="size-3.5" />
        </Button>
      </CardHeader>
      <CardContent className="p-4 sm:p-5">
        {scans.length === 0 ? (
          <EmptyState
            compact
            description="Start with a website you own or are explicitly authorized to assess. Completed results will appear here."
            title="No scans yet"
          />
        ) : (
          <ul className="divide-y divide-border/60">
            {scans.map((scan) => (
              <li className="flex min-w-0 items-center gap-3 py-3 first:pt-0 last:pb-0" key={scan.id}>
                <span aria-hidden="true" className="grid size-8 shrink-0 place-items-center rounded-lg border border-border/70 bg-muted/35 text-muted-foreground">
                  <Clock3 className="size-3.5" />
                </span>
                <div className="min-w-0 flex-1">
                  <Link className="block truncate font-mono text-xs text-foreground hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" href={`/scans/${scan.id}`} title={scan.target_url}>
                    {scan.target_url}
                  </Link>
                  <p className="mt-1 text-[10px] text-muted-foreground">{formatDate(scan.created_at)}</p>
                </div>
                <div className="flex shrink-0 flex-col items-end gap-1.5">
                  <ScanStatusBadge status={scan.status} />
                  <span className="text-[10px] tabular-nums text-muted-foreground">
                    {scan.score_available && scan.score !== null ? `Score ${scan.score}` : "No score"}
                  </span>
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

function formatDate(value: string | null) {
  if (!value) return "Date unavailable";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Date unavailable"
    : new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" }).format(date);
}
