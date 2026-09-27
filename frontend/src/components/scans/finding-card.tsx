import { ArrowUpRight, FileSearch, Wrench } from "lucide-react";
import { EmptyState } from "@/components/shared/empty-state";
import { SeverityBadge, type Severity } from "@/components/shared/severity-badge";
import { ScanStatusBadge, type ScanStatus } from "@/components/shared/scan-status-badge";
import { Card, CardContent } from "@/components/ui/card";

export type FindingView = {
  title: string;
  severity: Severity;
  status: ScanStatus;
  description: string;
  evidence?: string;
  recommendation: string;
};

export function FindingCard({ finding }: { finding?: FindingView }) {
  if (!finding) {
    return (
      <Card className="border-dashed border-border/80 bg-background/20 shadow-none">
        <CardContent className="p-3 sm:p-5">
          <EmptyState
            compact
            description="Finding cards will show observed evidence, why it matters, and remediation guidance after a real scan."
            title="No findings to display"
          />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-border/70 bg-card/80 shadow-none">
      <CardContent className="space-y-5 p-4 sm:p-5">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          <ScanStatusBadge status={finding.status} />
        </div>
        <div>
          <h3 className="text-sm font-semibold text-foreground">{finding.title}</h3>
          <p className="mt-2 text-xs leading-5 text-muted-foreground">{finding.description}</p>
        </div>
        <div className="grid gap-4 border-t border-border/60 pt-4 sm:grid-cols-2">
          <div>
            <p className="flex items-center gap-2 text-[10px] font-semibold tracking-wide text-muted-foreground uppercase">
              <FileSearch aria-hidden="true" className="size-3.5" /> Observed evidence
            </p>
            <p className="mt-2 break-words font-mono text-[11px] leading-5 text-foreground/85">{finding.evidence ?? "No evidence provided"}</p>
          </div>
          <div>
            <p className="flex items-center gap-2 text-[10px] font-semibold tracking-wide text-muted-foreground uppercase">
              <Wrench aria-hidden="true" className="size-3.5" /> Recommended next step
            </p>
            <p className="mt-2 text-xs leading-5 text-foreground/85">{finding.recommendation}</p>
          </div>
        </div>
        <p className="inline-flex items-center gap-1 text-[10px] text-muted-foreground">
          References will be linked when verified findings are connected <ArrowUpRight aria-hidden="true" className="size-3" />
        </p>
      </CardContent>
    </Card>
  );
}
