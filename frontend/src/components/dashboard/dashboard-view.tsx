"use client";

import { useEffect, useState } from "react";
import { AlertOctagon, AlertTriangle, CircleHelp, ShieldCheck, Siren } from "lucide-react";
import { NewScanDialog } from "@/components/app/new-scan-dialog";
import { CheckCoverage } from "@/components/dashboard/check-coverage";
import { RecentScans } from "@/components/dashboard/recent-scans";
import { SecurityScoreCard } from "@/components/dashboard/security-score-card";
import { SeverityOverview } from "@/components/dashboard/severity-overview";
import { MetricCard } from "@/components/shared/metric-card";
import { DashboardSkeleton } from "@/components/shared/loading-skeleton";
import { PageHeader } from "@/components/shared/page-header";
import { ScanApiErrorState } from "@/components/scans/scan-api-error";
import { scannerApi } from "@/lib/scanner/api-client";
import type { ScanListResponse } from "@/lib/scanner/types";

export function DashboardView() {
  const [requestNumber, setRequestNumber] = useState(0);
  const [state, setState] = useState<
    | { kind: "loading" }
    | { kind: "error"; error: unknown }
    | { kind: "loaded"; data: ScanListResponse }
  >({ kind: "loading" });

  useEffect(() => {
    let active = true;
    scannerApi.listScans({ limit: 100, offset: 0 })
      .then((data) => { if (active) setState({ kind: "loaded", data }); })
      .catch((error: unknown) => { if (active) setState({ kind: "error", error }); });
    return () => { active = false; };
  }, [requestNumber]);

  function retry() {
    setState({ kind: "loading" });
    setRequestNumber((current) => current + 1);
  }

  if (state.kind === "loading") return <DashboardSkeleton />;
  if (state.kind === "error") {
    return (
      <div className="space-y-7">
        <PageHeader
          actions={<NewScanDialog />}
          description="A concise view of your authenticated assessment activity and the security signals WebGuard reviews."
          eyebrow="OVERVIEW"
          title="Security dashboard"
        />
        <ScanApiErrorState error={state.error} onRetry={retry} title="Your scan history is unavailable" />
      </div>
    );
  }

  const { data } = state;
  const latestCompleted = data.items.find((scan) => scan.status === "completed") ?? null;
  const latestCounts = latestCompleted?.severity_counts ?? null;
  const detail = latestCompleted ? "Latest completed scan" : "No completed scan yet";

  return (
    <div className="space-y-7">
      <PageHeader
        actions={<NewScanDialog />}
        description="A concise view of your assessment activity and the security signals WebGuard is designed to review."
        eyebrow="OVERVIEW"
        title="Security dashboard"
      />

      <section aria-label="Scan and finding summary" className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <MetricCard detail="In your account" icon={ShieldCheck} label="Total scans" tone="neutral" value={String(data.total)} />
        <MetricCard detail={detail} icon={AlertOctagon} label="Critical findings" tone="critical" value={latestCounts ? String(latestCounts.critical) : "—"} />
        <MetricCard detail={detail} icon={Siren} label="High findings" tone="high" value={latestCounts ? String(latestCounts.high) : "—"} />
        <MetricCard detail={detail} icon={AlertTriangle} label="Medium findings" tone="medium" value={latestCounts ? String(latestCounts.medium) : "—"} />
        <MetricCard detail={detail} icon={CircleHelp} label="Low findings" tone="low" value={latestCounts ? String(latestCounts.low) : "—"} />
      </section>

      <section aria-label="Latest security score and severity overview" className="grid gap-4 xl:grid-cols-12">
        <div className="xl:col-span-7"><SecurityScoreCard scan={latestCompleted} /></div>
        <div className="xl:col-span-5"><SeverityOverview counts={latestCounts} /></div>
      </section>

      <section aria-label="Recent scans and scanner coverage" className="grid gap-4 2xl:grid-cols-[1.15fr_0.85fr]">
        <RecentScans scans={data.items.slice(0, 5)} />
        <CheckCoverage />
      </section>
    </div>
  );
}
