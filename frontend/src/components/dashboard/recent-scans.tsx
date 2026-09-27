import Link from "next/link";
import { ArrowRight, Clock3 } from "lucide-react";
import { EmptyState } from "@/components/shared/empty-state";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function RecentScans() {
  return (
    <Card className="border-border/70 bg-card/80 shadow-none">
      <CardHeader className="flex-row items-center justify-between gap-3 border-b border-border/60 pb-4">
        <div>
          <p className="text-[10px] font-semibold tracking-[0.16em] text-muted-foreground uppercase">Activity</p>
          <CardTitle className="mt-1.5 text-base">Recent scans</CardTitle>
        </div>
        <Button render={<Link href="/scans" />} size="sm" variant="ghost">
          Scan history <ArrowRight aria-hidden="true" className="size-3.5" />
        </Button>
      </CardHeader>
      <CardContent className="p-4 sm:p-5">
        <EmptyState
          compact
          description="This preview is not connected to scan records yet. Your own history will appear here when data access is connected."
          title="No live scan data"
        />
        <p className="mt-4 flex items-center justify-center gap-1.5 text-[10px] text-muted-foreground/80">
          <Clock3 aria-hidden="true" className="size-3" /> History will be sorted by scan date
        </p>
      </CardContent>
    </Card>
  );
}
