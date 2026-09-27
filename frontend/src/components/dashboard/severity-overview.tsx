import { AlertOctagon, AlertTriangle, Info, ShieldAlert } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge, type Severity } from "@/components/shared/severity-badge";

const severities: { severity: Severity; icon: typeof AlertOctagon }[] = [
  { severity: "critical", icon: AlertOctagon },
  { severity: "high", icon: ShieldAlert },
  { severity: "medium", icon: AlertTriangle },
  { severity: "low", icon: Info },
];

export function SeverityOverview() {
  return (
    <Card className="h-full border-border/70 bg-card/80 shadow-none">
      <CardHeader className="flex-row items-center justify-between gap-3 pb-3">
        <div>
          <p className="text-[10px] font-semibold tracking-[0.16em] text-muted-foreground uppercase">Findings</p>
          <CardTitle className="mt-1.5 text-base">Severity overview</CardTitle>
        </div>
        <span className="text-[10px] text-muted-foreground">— total</span>
      </CardHeader>
      <CardContent className="space-y-1 px-4 pb-4 sm:px-5 sm:pb-5">
        {severities.map(({ severity, icon: Icon }) => (
          <div className="flex items-center gap-3 rounded-lg px-2 py-2.5" key={severity}>
            <span className="grid size-7 place-items-center rounded-md bg-muted/60 text-muted-foreground">
              <Icon aria-hidden="true" className="size-3.5" />
            </span>
            <SeverityBadge severity={severity} />
            <span aria-label={`${severity} findings: not available`} className="ml-auto text-sm font-semibold tabular-nums text-muted-foreground">—</span>
          </div>
        ))}
        <p className="border-t border-border/60 px-2 pt-3 text-[10px] leading-4 text-muted-foreground">
          Counts will appear after scan data is connected.
        </p>
      </CardContent>
    </Card>
  );
}
