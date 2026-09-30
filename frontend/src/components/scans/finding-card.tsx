import { FileSearch, Wrench } from "lucide-react";
import { AiFindingGuidance } from "@/components/scans/ai-guidance";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { ScanStatusBadge } from "@/components/shared/scan-status-badge";
import { Card, CardContent } from "@/components/ui/card";
import { checkLabel, formatEvidence } from "@/lib/scanner/display";
import type { Finding, FindingAiGuidance } from "@/lib/scanner/types";

export function FindingCard({
  finding,
  scanId,
  aiAvailable,
  aiGuidance,
}: {
  finding: Finding;
  scanId: string;
  aiAvailable: boolean;
  aiGuidance: FindingAiGuidance | null;
}) {
  return (
    <Card className="border-border/70 bg-card/80 shadow-none">
      <CardContent className="space-y-5 p-4 sm:p-5">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          <ScanStatusBadge status={finding.status} />
          <span className="text-[10px] text-muted-foreground">{checkLabel(finding.check_id)}</span>
        </div>
        <div>
          <h3 className="text-sm font-semibold text-foreground">{finding.title}</h3>
          <p className="mt-2 text-xs leading-5 text-muted-foreground">{finding.summary}</p>
          <p className="mt-3 text-xs leading-5 text-foreground/90">{finding.why_it_matters}</p>
        </div>
        <div className="grid gap-4 border-t border-border/60 pt-4 sm:grid-cols-2">
          <div>
            <p className="flex items-center gap-2 text-[10px] font-semibold tracking-wide text-muted-foreground uppercase">
              <FileSearch aria-hidden="true" className="size-3.5" /> Observed evidence
            </p>
            <p className="mt-2 break-words font-mono text-[11px] leading-5 text-foreground/85">{formatEvidence(finding.evidence)}</p>
          </div>
          <div>
            <p className="flex items-center gap-2 text-[10px] font-semibold tracking-wide text-muted-foreground uppercase">
              <Wrench aria-hidden="true" className="size-3.5" /> Recommended next step
            </p>
            <p className="mt-2 text-xs leading-5 text-foreground/85">{finding.remediation}</p>
          </div>
        </div>
        <AiFindingGuidance
          scanId={scanId}
          findingId={finding.id}
          available={aiAvailable}
          initialGuidance={aiGuidance}
        />
      </CardContent>
    </Card>
  );
}
