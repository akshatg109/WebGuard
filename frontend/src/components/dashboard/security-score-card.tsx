import { ArrowUpRight, CircleHelp } from "lucide-react";
import { ScanStatusBadge } from "@/components/shared/scan-status-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ScanStatus, ScoreConfidence } from "@/lib/scanner/types";

export type ScoreCardScan = {
  target_url: string;
  status: ScanStatus;
  score: number | null;
  score_available: boolean;
  confidence: ScoreConfidence | null;
  scoring_version?: string | null;
  score_unavailability_reasons?: string[];
};

const UNAVAILABILITY_MESSAGES: Record<string, string> = {
  insufficient_point_coverage: "Evidence covered too few score points.",
  insufficient_check_coverage: "Too few score-relevant checks were resolved.",
};

export function SecurityScoreCard({ scan }: { scan: ScoreCardScan | null }) {
  const hasScore = Boolean(scan?.status === "completed" && scan.score_available && scan.score !== null);
  const value = hasScore ? scan?.score ?? 0 : null;
  const circumference = 2 * Math.PI * 56;
  const progressOffset = value === null ? circumference : circumference * (1 - value / 100);
  const description = !scan
    ? "WebGuard only shows a score after a real scan. There is no sample score in this view."
    : hasScore
      ? scan.confidence === "limited"
        ? "This score is based on limited evidence. Review the coverage and check explanations before comparing results."
        : "A WebGuard configuration score based on evidence observed by these checks—not a guarantee of security."
      : scan.status === "failed"
        ? "This scan did not complete, so no security score is available."
        : scan.status === "completed"
          ? "Evidence coverage requirements were not met, so WebGuard has withheld a numeric score."
          : "This scan has not completed. No score is shown until the assessment finishes.";
  const unavailabilityMessages = scan?.score_unavailability_reasons
    ?.map((reason) => UNAVAILABILITY_MESSAGES[reason] ?? "Evidence coverage requirements were not met.")
    .filter((message, index, messages) => messages.indexOf(message) === index);

  return (
    <Card className="h-full overflow-hidden border-border/70 bg-card/80 shadow-none">
      <CardHeader className="flex-row items-start justify-between gap-3 pb-0">
        <div>
          <p className="text-[10px] font-semibold tracking-[0.16em] text-primary uppercase">Security posture</p>
          <CardTitle className="mt-2 text-base">Overall security score</CardTitle>
        </div>
        {scan ? scan.status === "completed" ? (
          <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[10px] ${hasScore ? "border-severity-passed/25 bg-severity-passed/10 text-severity-passed" : "border-severity-medium/25 bg-severity-medium/10 text-severity-medium"}`}>
            <CircleHelp aria-hidden="true" className="size-3" /> {hasScore ? "Score available" : "Score unavailable"}
          </span>
        ) : (
          <ScanStatusBadge status={scan.status} />
        ) : (
          <span aria-label="Score not calculated" className="inline-flex items-center gap-1.5 rounded-md border border-border bg-muted/50 px-2 py-1 text-[10px] text-muted-foreground">
            <CircleHelp aria-hidden="true" className="size-3" /> Not calculated
          </span>
        )}
      </CardHeader>
      <CardContent className="flex flex-col items-center gap-5 px-5 pb-5 pt-6 sm:flex-row sm:items-center sm:gap-7 sm:px-6 sm:pb-6">
        <div
          aria-label={hasScore ? `Security configuration score ${value} out of 100` : "No security score available"}
          className="relative grid size-36 shrink-0 place-items-center"
          role="img"
        >
          <svg aria-hidden="true" className="absolute inset-0 size-full -rotate-90" viewBox="0 0 144 144">
            <circle cx="72" cy="72" fill="none" r="56" stroke="var(--border)" strokeWidth="6" />
            {hasScore && <circle cx="72" cy="72" fill="none" r="56" stroke="var(--primary)" strokeDasharray={circumference} strokeDashoffset={progressOffset} strokeLinecap="round" strokeWidth="6" />}
            <circle cx="72" cy="72" fill="none" r="46" stroke="color-mix(in oklch, var(--primary) 18%, transparent)" strokeWidth="1" />
          </svg>
          <div className="text-center">
            <span className="block text-4xl leading-none font-semibold tracking-[-0.07em] text-foreground">{hasScore ? value : "—"}</span>
            <span className="mt-2 block text-[10px] font-semibold tracking-[0.12em] text-muted-foreground uppercase">out of 100</span>
          </div>
        </div>
        <div className="min-w-0 max-w-sm text-center sm:text-left">
          <p className="break-all text-sm font-semibold text-foreground">{scan ? scan.target_url : "Your first assessment is waiting"}</p>
          <p className="mt-2 text-xs leading-5 text-muted-foreground">{description}</p>
          {scan?.confidence && <p className="mt-2 text-[11px] text-muted-foreground">Evidence confidence: <span className="font-medium text-foreground">{scan.confidence}</span></p>}
          {scan?.scoring_version && <p className="mt-1 text-[11px] text-muted-foreground">Scoring version {scan.scoring_version}</p>}
          {unavailabilityMessages && unavailabilityMessages.length > 0 && (
            <p className="mt-2 text-[11px] leading-5 text-muted-foreground">{unavailabilityMessages.join(" · ")}</p>
          )}
          <p className="mt-4 inline-flex items-center gap-1.5 text-[11px] font-medium text-muted-foreground">
            Score methodology <ArrowUpRight aria-hidden="true" className="size-3" />
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
