import { AlertOctagon, AlertTriangle, CircleHelp, Info, ShieldAlert } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/shared/severity-badge";
import type { SeverityCounts } from "@/lib/scanner/types";

const severities: { severity: keyof SeverityCounts; icon: typeof AlertOctagon }[] = [
  { severity: "critical", icon: AlertOctagon },
  { severity: "high", icon: ShieldAlert },
  { severity: "medium", icon: AlertTriangle },
  { severity: "low", icon: Info },
  { severity: "informational", icon: CircleHelp },
];

export function SeverityOverview({ counts }: { counts: SeverityCounts | null }) {
  const total = counts ? Object.values(counts).reduce((sum, count) => sum + count, 0) : null;
  return (
    <Card className="h-full border-border/70 bg-card/80 shadow-none">
      <CardHeader className="flex-row items-center justify-between gap-3 pb-3">
        <div>
          <p className="text-[10px] font-semibold tracking-[0.16em] text-muted-foreground uppercase">Findings</p>
          <CardTitle className="mt-1.5 text-base">Severity overview</CardTitle>
        </div>
        <span className="text-[10px] text-muted-foreground">{total === null ? "No completed scan" : `${total} issues`}</span>
      </CardHeader>
      <CardContent className="space-y-1 px-4 pb-4 sm:px-5 sm:pb-5">
        {severities.map(({ severity, icon: Icon }) => (
          <div className="flex items-center gap-3 rounded-lg px-2 py-2.5" key={severity}>
            <span className="grid size-7 place-items-center rounded-md bg-muted/60 text-muted-foreground">
              <Icon aria-hidden="true" className="size-3.5" />
            </span>
            <SeverityBadge severity={severity} />
            <span aria-label={`${severity} findings: ${counts ? counts[severity] : "not available"}`} className="ml-auto text-sm font-semibold tabular-nums text-muted-foreground">
              {counts ? counts[severity] : "—"}
            </span>
          </div>
        ))}
        <p className="border-t border-border/60 px-2 pt-3 text-[10px] leading-4 text-muted-foreground">
          {counts ? "Counts include failed, warning, and unassessed checks from the latest completed scan." : "A severity summary is available after a scan completes."}
        </p>
      </CardContent>
    </Card>
  );
}
