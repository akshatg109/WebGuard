import Link from "next/link";
import { ArrowLeft, Clock3, Globe2 } from "lucide-react";
import { FindingCard } from "@/components/scans/finding-card";
import { SecurityCheckList } from "@/components/scans/security-check-list";
import { SecurityScoreCard } from "@/components/dashboard/security-score-card";
import { SeverityOverview } from "@/components/dashboard/severity-overview";
import { EmptyState } from "@/components/shared/empty-state";
import { PageHeader } from "@/components/shared/page-header";
import { ScanStatusBadge } from "@/components/shared/scan-status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type ScanDetailsProps = { params: Promise<{ id: string }> };

export default async function ScanDetailsPage({ params }: ScanDetailsProps) {
  const { id } = await params;

  return (
    <div className="space-y-7">
      <PageHeader
        actions={<Button render={<Link href="/scans" />} variant="outline"><ArrowLeft aria-hidden="true" className="size-4" /> Back to scans</Button>}
        description="A report layout preview. No scan record has been loaded for this route."
        eyebrow="REPORT TEMPLATE"
        title="Scan report"
      />

      <Card className="border-border/70 bg-card/80 shadow-none">
        <CardContent className="grid gap-5 p-4 sm:grid-cols-[1.5fr_1fr_1fr] sm:items-center sm:p-5">
          <div className="min-w-0">
            <p className="text-[10px] font-semibold tracking-[0.15em] text-muted-foreground uppercase">Target URL</p>
            <p className="mt-2 flex items-center gap-2 font-mono text-sm text-muted-foreground">
              <Globe2 aria-hidden="true" className="size-4 shrink-0" /> Not available in preview
            </p>
          </div>
          <div>
            <p className="text-[10px] font-semibold tracking-[0.15em] text-muted-foreground uppercase">Scan date</p>
            <p className="mt-2 flex items-center gap-2 text-xs text-muted-foreground">
              <Clock3 aria-hidden="true" className="size-3.5" /> Not available
            </p>
          </div>
          <div className="flex items-center gap-2 sm:justify-end">
            <ScanStatusBadge status="not-run" />
            <span className="font-mono text-[10px] text-muted-foreground">ID {id}</span>
          </div>
        </CardContent>
      </Card>

      <section aria-label="Report score and severity summary" className="grid gap-4 xl:grid-cols-12">
        <div className="xl:col-span-7"><SecurityScoreCard /></div>
        <div className="xl:col-span-5"><SeverityOverview /></div>
      </section>

      <section className="space-y-3" aria-labelledby="findings-heading">
        <SectionHeading id="findings-heading" title="Findings" description="Observed issues and their recommended remediation." />
        <FindingCard />
      </section>

      <section className="grid gap-4 xl:grid-cols-2">
        <SecurityCheckList />
        <Card className="border-border/70 bg-card/80 shadow-none">
          <CardHeader>
            <p className="text-[10px] font-semibold tracking-[0.16em] text-muted-foreground uppercase">Detected stack</p>
            <CardTitle className="mt-1.5 text-base">Technologies</CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4 sm:px-5 sm:pb-5">
            <EmptyState compact description="Technology indicators are shown only when returned by an actual scan." title="No technology data" />
          </CardContent>
        </Card>
      </section>

      <section aria-labelledby="remediation-heading" className="space-y-3">
        <SectionHeading id="remediation-heading" title="Remediation & next steps" description="Guidance will be tied to verified findings from your own scan." />
        <Card className="border-border/70 bg-card/80 shadow-none">
          <CardContent className="p-4 sm:p-5">
            <EmptyState compact description="There are no recommended actions until scan findings are available." title="No actions to take yet" />
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
