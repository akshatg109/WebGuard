import { FileClock } from "lucide-react";
import { ScanHistoryTable } from "@/components/scans/scan-history-table";
import { PageHeader } from "@/components/shared/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { scanPreviewData } from "@/data/scan-preview";

export default function ScansPage() {
  return (
    <div className="space-y-7">
      <PageHeader
        description="Review completed assessments and return to a report. History will populate when the scan API is connected."
        eyebrow="ASSESSMENT HISTORY"
        title="Scans"
      />
      <Card className="border-border/70 bg-card/80 shadow-none">
        <CardContent className="flex flex-col gap-3 px-4 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-5">
          <div className="flex items-center gap-3">
            <span className="grid size-9 place-items-center rounded-lg border border-border/70 bg-muted/35 text-muted-foreground">
              <FileClock aria-hidden="true" className="size-4" />
            </span>
            <div>
              <p className="text-xs font-medium text-foreground">Scan history</p>
              <p className="mt-1 text-[11px] text-muted-foreground">Private to your authenticated account</p>
            </div>
          </div>
          <span aria-live="polite" className="w-fit rounded-md border border-border/70 bg-background/35 px-2.5 py-1 text-[10px] font-medium text-muted-foreground">
            {scanPreviewData.length} records connected
          </span>
        </CardContent>
      </Card>
      <ScanHistoryTable data={scanPreviewData} />
    </div>
  );
}
