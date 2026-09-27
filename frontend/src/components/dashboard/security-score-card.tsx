import { ArrowUpRight, CircleHelp } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function SecurityScoreCard() {
  return (
    <Card className="h-full overflow-hidden border-border/70 bg-card/80 shadow-none">
      <CardHeader className="flex-row items-start justify-between gap-3 pb-0">
        <div>
          <p className="text-[10px] font-semibold tracking-[0.16em] text-primary uppercase">Security posture</p>
          <CardTitle className="mt-2 text-base">Overall security score</CardTitle>
        </div>
        <span aria-label="Score not calculated" className="inline-flex items-center gap-1.5 rounded-md border border-border bg-muted/50 px-2 py-1 text-[10px] text-muted-foreground">
          <CircleHelp aria-hidden="true" className="size-3" /> Not calculated
        </span>
      </CardHeader>
      <CardContent className="flex flex-col items-center gap-5 px-5 pb-5 pt-6 sm:flex-row sm:items-center sm:gap-7 sm:px-6 sm:pb-6">
        <div aria-label="No score available" className="relative grid size-36 shrink-0 place-items-center" role="img">
          <svg aria-hidden="true" className="absolute inset-0 size-full -rotate-90" viewBox="0 0 144 144">
            <circle cx="72" cy="72" fill="none" r="62" stroke="var(--border)" strokeDasharray="2 7" strokeLinecap="round" strokeWidth="5" />
            <circle cx="72" cy="72" fill="none" r="50" stroke="color-mix(in oklch, var(--primary) 22%, transparent)" strokeWidth="1" />
          </svg>
          <div className="text-center">
            <span className="block text-4xl leading-none font-semibold tracking-[-0.07em] text-foreground">—</span>
            <span className="mt-2 block text-[10px] font-semibold tracking-[0.12em] text-muted-foreground uppercase">out of 100</span>
          </div>
        </div>
        <div className="max-w-sm text-center sm:text-left">
          <p className="text-sm font-semibold text-foreground">Your first assessment is waiting</p>
          <p className="mt-2 text-xs leading-5 text-muted-foreground">
            WebGuard only shows a score after a real scan. There is no sample score in this preview.
          </p>
          <p className="mt-4 inline-flex items-center gap-1.5 text-[11px] font-medium text-muted-foreground">
            Score methodology <ArrowUpRight aria-hidden="true" className="size-3" />
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
