import { AlertOctagon, AlertTriangle, CircleHelp, ShieldCheck, Siren } from "lucide-react";
import { NewScanDialog } from "@/components/app/new-scan-dialog";
import { CheckCoverage } from "@/components/dashboard/check-coverage";
import { RecentScans } from "@/components/dashboard/recent-scans";
import { SecurityScoreCard } from "@/components/dashboard/security-score-card";
import { SeverityOverview } from "@/components/dashboard/severity-overview";
import { MetricCard } from "@/components/shared/metric-card";
import { PageHeader } from "@/components/shared/page-header";

export default function DashboardPage() {
  return (
    <div className="space-y-7">
      <PageHeader
        actions={<NewScanDialog />}
        description="A concise view of assessment activity and the security signals WebGuard is designed to review."
        eyebrow="OVERVIEW"
        title="Security dashboard"
      />

      <section aria-label="Scan and finding summary" className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <MetricCard icon={ShieldCheck} label="Total scans" tone="neutral" />
        <MetricCard icon={AlertOctagon} label="Critical findings" tone="critical" />
        <MetricCard icon={Siren} label="High findings" tone="high" />
        <MetricCard icon={AlertTriangle} label="Medium findings" tone="medium" />
        <MetricCard icon={CircleHelp} label="Low findings" tone="low" />
      </section>

      <section aria-label="Security score and severity overview" className="grid gap-4 xl:grid-cols-12">
        <div className="xl:col-span-7"><SecurityScoreCard /></div>
        <div className="xl:col-span-5"><SeverityOverview /></div>
      </section>

      <section aria-label="Recent scans and planned checks" className="grid gap-4 2xl:grid-cols-[1.15fr_0.85fr]">
        <RecentScans />
        <CheckCoverage />
      </section>
    </div>
  );
}
