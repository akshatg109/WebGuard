import { CircleDashed } from "lucide-react";
import { ScanStatusBadge } from "@/components/shared/scan-status-badge";
import { EmptyState } from "@/components/shared/empty-state";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { checkLabel, formatEvidence } from "@/lib/scanner/display";
import type { CheckResult } from "@/lib/scanner/types";

export function SecurityCheckList({ checkResults }: { checkResults: CheckResult[] }) {
  const scoringVersion = checkResults.find((item) => item.scoring_relevant)?.scoring_version;

  return (
    <Card className="min-w-0 border-border/70 bg-card/80 shadow-none">
      <CardHeader className="flex-row items-center justify-between gap-3">
        <div>
          <p className="text-[10px] font-semibold tracking-[0.16em] text-muted-foreground uppercase">Observed results</p>
          <CardTitle className="mt-1.5 text-base">Security checks</CardTitle>
        </div>
        <span className="text-[10px] text-muted-foreground">{checkResults.length} checks</span>
      </CardHeader>
      <CardContent className="px-4 pb-4 sm:px-5 sm:pb-5">
        {checkResults.length === 0 ? (
          <EmptyState compact description="Check results are available when a scan has completed." title="No check results yet" />
        ) : (
          <>
            <ul className="divide-y divide-border/60">
              {checkResults.map((result) => {
                const deduction = result.score_explanation.deduction_points;
                return (
                  <li className="py-3 first:pt-0 last:pb-0" key={result.check_id}>
                    <div className="flex min-w-0 items-center justify-between gap-3">
                      <span className="flex min-w-0 items-center gap-2.5 text-xs text-foreground/90">
                        <CircleDashed aria-hidden="true" className="size-3.5 shrink-0 text-muted-foreground" />
                        <span className="truncate">{checkLabel(result.check_id)}</span>
                      </span>
                      <ScanStatusBadge status={result.status} />
                    </div>
                    <p className="mt-2 pl-6 text-[11px] leading-5 text-muted-foreground">{result.reason}</p>
                    {Object.keys(result.evidence).length > 0 && (
                      <p className="mt-1 pl-6 break-words font-mono text-[10px] leading-4 text-muted-foreground/80">
                        {formatEvidence(result.evidence)}
                      </p>
                    )}
                    <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 pl-6 text-[10px] text-muted-foreground/75">
                      {result.scoring_relevant && <span>Scoring check · v{result.scoring_version}</span>}
                      {typeof deduction === "number" && deduction > 0 && <span>{deduction} point deduction</span>}
                      <span>Check v{result.check_version}</span>
                    </div>
                  </li>
                );
              })}
            </ul>
            {scoringVersion && <p className="mt-4 border-t border-border/60 pt-3 text-[10px] text-muted-foreground">Scoring methodology version {scoringVersion}</p>}
          </>
        )}
      </CardContent>
    </Card>
  );
}
