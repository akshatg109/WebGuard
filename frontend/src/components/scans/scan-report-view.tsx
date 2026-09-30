"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ArrowLeft, Clock3, Globe2, ShieldAlert } from "lucide-react";
import { FindingCard } from "@/components/scans/finding-card";
import { AiSummaryCard } from "@/components/scans/ai-guidance";
import { ScanApiErrorState } from "@/components/scans/scan-api-error";
import { ScoreBreakdownCard } from "@/components/scans/score-breakdown-card";
import { SecurityCheckList } from "@/components/scans/security-check-list";
import { SecurityScoreCard } from "@/components/dashboard/security-score-card";
import { SeverityOverview } from "@/components/dashboard/severity-overview";
import { EmptyState } from "@/components/shared/empty-state";
import { ScanDetailsSkeleton } from "@/components/shared/loading-skeleton";
import { PageHeader } from "@/components/shared/page-header";
import { ScanStatusBadge } from "@/components/shared/scan-status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { friendlyScanError, scannerApi } from "@/lib/scanner/api-client";
import { actionableFindings, scoreDisplay } from "@/lib/scanner/display";
import type { Scan } from "@/lib/scanner/types";

export function ScanReportView({ scanId }: { scanId: string }) {
  const [requestNumber, setRequestNumber] = useState(0);
  const [state, setState] = useState<
    | { kind: "loading" }
    | { kind: "error"; error: unknown }
    | { kind: "loaded"; scan: Scan }
  >({ kind: "loading" });

  useEffect(() => {
    let active = true;
    scannerApi.getScan(scanId)
      .then((scan) => { if (active) setState({ kind: "loaded", scan }); })
      .catch((error: unknown) => { if (active) setState({ kind: "error", error }); });
    return () => { active = false; };
  }, [scanId, requestNumber]);

  function retry() {
    setState({ kind: "loading" });
    setRequestNumber((current) => current + 1);
  }

  if (state.kind === "loading") return <ScanDetailsSkeleton />;
  if (state.kind === "error") {
    return (
      <div className="space-y-7">
        <PageHeader
          actions={<Button render={<Link href="/scans" />} variant="outline"><ArrowLeft aria-hidden="true" className="size-4" /> Back to scans</Button>}
          description="View the results stored for your authenticated account."
          eyebrow="SCAN REPORT"
          title="Scan report"
        />
        <ScanApiErrorState error={state.error} onRetry={retry} title="This scan could not be loaded" />
      </div>
    );
  }

  const { scan } = state;
  const severity = scoreDisplay(scan);
  const findings = actionableFindings(scan);

  return (
    <div className="space-y-7">
      <PageHeader
        actions={<Button render={<Link href="/scans" />} variant="outline"><ArrowLeft aria-hidden="true" className="size-4" /> Back to scans</Button>}
        description={scan.summary}
        eyebrow="SCAN REPORT"
        title="Security assessment"
      />

      {scan.status === "failed" && (
        <div className="flex items-start gap-3 rounded-xl border border-severity-high/25 bg-severity-high/5 p-4" role="status">
          <ShieldAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-severity-high" />
          <div>
            <p className="text-xs font-semibold text-foreground">The scan failed</p>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">{friendlyScanError(scan.error?.code)}</p>
          </div>
        </div>
      )}
      {(scan.status === "pending" || scan.status === "running") && (
        <div className="rounded-xl border border-primary/25 bg-primary/5 p-4" role="status" aria-live="polite">
          <p className="text-xs font-semibold text-foreground">Scan {scan.status}</p>
          <p className="mt-1 text-xs leading-5 text-muted-foreground">This API runs scans synchronously. Refresh the report later if it has not completed; no background scan is assumed.</p>
        </div>
      )}

      <Card className="border-border/70 bg-card/80 shadow-none">
        <CardContent className="grid min-w-0 gap-5 p-4 sm:grid-cols-[1.5fr_1fr_auto] sm:items-center sm:p-5">
          <div className="min-w-0">
            <p className="text-[10px] font-semibold tracking-[0.15em] text-muted-foreground uppercase">Target URL</p>
            <p className="mt-2 flex min-w-0 items-start gap-2 break-all font-mono text-xs leading-5 text-foreground">
              <Globe2 aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted-foreground" /> {scan.target_url}
            </p>
            {scan.normalized_url && scan.normalized_url !== scan.target_url && (
              <p className="mt-2 break-all pl-6 font-mono text-[10px] leading-4 text-muted-foreground">
                Normalized target: {scan.normalized_url}
              </p>
            )}
          </div>
          <div>
            <p className="text-[10px] font-semibold tracking-[0.15em] text-muted-foreground uppercase">{scan.completed_at ? "Completed" : "Created"}</p>
            <p className="mt-2 flex items-center gap-2 text-xs text-muted-foreground">
              <Clock3 aria-hidden="true" className="size-3.5" /> {formatDate(scan.completed_at ?? scan.created_at)}
            </p>
            {scan.duration_ms !== null && <p className="mt-1 pl-5 text-[10px] text-muted-foreground">Duration {formatDuration(scan.duration_ms)}</p>}
          </div>
          <div className="flex flex-wrap items-center gap-2 sm:justify-end">
            <ScanStatusBadge status={scan.status} />
            <span className="font-mono text-[10px] text-muted-foreground">ID {scan.id}</span>
          </div>
        </CardContent>
      </Card>

      <section aria-label="Security score and severity overview" className="grid min-w-0 gap-4 xl:grid-cols-12">
        <div className="min-w-0 xl:col-span-7"><SecurityScoreCard scan={scan} /></div>
        <div className="min-w-0 xl:col-span-5"><SeverityOverview counts={severity?.counts ?? null} /></div>
      </section>

      <ScoreBreakdownCard breakdown={scan.score_details} />

      <AiSummaryCard
        key={scan.id}
        scanId={scan.id}
        available={scan.ai_available}
        initialSummary={scan.ai_summary}
      />

      <section aria-labelledby="findings-heading" className="space-y-3">
        <SectionHeading
          id="findings-heading"
          title="Findings"
          description="Checks that returned a failure, warning, or error. Passed and not-applicable results are listed separately below."
        />
        {findings.length > 0 ? (
          <div className="space-y-3">
            {findings.map((finding) => (
              <FindingCard
                finding={finding}
                scanId={scan.id}
                aiAvailable={scan.ai_available}
                aiGuidance={scan.ai_explanations.find((item) => item.finding_id === finding.id) ?? null}
                key={`${scan.id}:${finding.check_id}`}
              />
            ))}
          </div>
        ) : (
          <EmptyState
            compact
            description={scan.status === "completed"
              ? "No failed, warning, or error checks were returned. This limited configuration review does not prove the website is secure."
              : scan.status === "failed"
                ? "The scan failed before usable finding results were available."
                : "Finding results will appear when the scan completes."}
            title={scan.status === "completed" ? "No actionable findings" : "Findings not available yet"}
          />
        )}
      </section>

      <section aria-label="Check results and detected technologies" className="grid min-w-0 gap-4 xl:grid-cols-2">
        <SecurityCheckList checkResults={scan.check_results} />
        <Card className="min-w-0 border-border/70 bg-card/80 shadow-none">
          <CardHeader>
            <p className="text-[10px] font-semibold tracking-[0.16em] text-muted-foreground uppercase">Passive indicators</p>
            <CardTitle className="mt-1.5 text-base">Technologies</CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4 sm:px-5 sm:pb-5">
            {scan.technologies.length === 0 ? (
              <EmptyState compact description="No technology indicators were returned by this scan." title="No technologies detected" />
            ) : (
              <ul className="divide-y divide-border/60">
                {scan.technologies.map((technology) => (
                  <li className="flex flex-wrap items-center justify-between gap-2 py-3 first:pt-0 last:pb-0" key={`${technology.name}:${technology.category}`}>
                    <div className="min-w-0">
                      <p className="text-xs font-medium text-foreground">{technology.name}</p>
                      <p className="mt-1 text-[10px] capitalize text-muted-foreground">{technology.category}</p>
                    </div>
                    <span className="rounded-md border border-border/70 bg-muted/30 px-2 py-1 text-[10px] capitalize text-muted-foreground">
                      {technology.confidence ? `${technology.confidence} confidence` : "Confidence unavailable"}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </section>
    </div>
  );
}

function SectionHeading({ id, title, description }: { id: string; title: string; description: string }) {
  return (
    <div>
      <h2 className="text-base font-semibold tracking-tight text-foreground" id={id}>{title}</h2>
      <p className="mt-1 text-xs leading-5 text-muted-foreground">{description}</p>
    </div>
  );
}

function formatDate(value: string | null) {
  if (!value) return "Date unavailable";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Date unavailable"
    : new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function formatDuration(milliseconds: number) {
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return "unavailable";
  if (milliseconds < 1_000) return `${milliseconds} ms`;
  return `${(milliseconds / 1_000).toFixed(1)} s`;
}
