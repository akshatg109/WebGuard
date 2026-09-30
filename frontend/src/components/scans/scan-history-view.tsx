"use client";

import { useEffect, useState } from "react";
import { FileClock } from "lucide-react";
import { NewScanDialog } from "@/components/app/new-scan-dialog";
import { ScanHistoryTable } from "@/components/scans/scan-history-table";
import { ScanApiErrorState } from "@/components/scans/scan-api-error";
import { ScanListSkeleton } from "@/components/shared/loading-skeleton";
import { PageHeader } from "@/components/shared/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { scannerApi } from "@/lib/scanner/api-client";
import type { ScanListResponse } from "@/lib/scanner/types";

export function ScanHistoryView() {
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

  if (state.kind === "loading") {
    return (
      <div className="space-y-7">
        <PageHeader actions={<NewScanDialog />} description="Your private, authenticated scan history." eyebrow="ASSESSMENT HISTORY" title="Scans" />
        <ScanListSkeleton />
      </div>
    );
  }

  if (state.kind === "error") {
    return (
      <div className="space-y-7">
        <PageHeader actions={<NewScanDialog />} description="Your private, authenticated scan history." eyebrow="ASSESSMENT HISTORY" title="Scans" />
        <ScanApiErrorState error={state.error} onRetry={retry} title="Scan history could not be loaded" />
      </div>
    );
  }

  const { data } = state;
  return (
    <div className="space-y-7">
      <PageHeader
        actions={<NewScanDialog />}
        description="Review your completed and failed assessments, then return to the exact result record."
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
            {data.total} {data.total === 1 ? "record" : "records"}{data.total > data.items.length ? ` · latest ${data.items.length} loaded` : ""}
          </span>
        </CardContent>
      </Card>
      <ScanHistoryTable data={data.items} />
    </div>
  );
}
