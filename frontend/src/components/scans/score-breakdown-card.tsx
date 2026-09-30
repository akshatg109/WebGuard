import { EmptyState } from "@/components/shared/empty-state";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ScoreBreakdown } from "@/lib/scanner/types";

const CATEGORY_LABELS: Record<string, string> = {
  transport: "Transport security",
  headers: "Security headers",
  exposure: "Information exposure",
  cookies: "Cookie attributes",
  content: "Content security",
  technology: "Technology indicators",
};

export function ScoreBreakdownCard({ breakdown }: { breakdown: ScoreBreakdown }) {
  const categories = breakdown.categories ?? [];
  const coverage = breakdown.check_coverage_percent;

  return (
    <Card className="min-w-0 border-border/70 bg-card/80 shadow-none">
      <CardHeader className="flex-row items-center justify-between gap-3">
        <div>
          <p className="text-[10px] font-semibold tracking-[0.16em] text-muted-foreground uppercase">Score methodology</p>
          <CardTitle className="mt-1.5 text-base">Category breakdown</CardTitle>
        </div>
        <span className="text-[10px] text-muted-foreground">
          {typeof coverage === "number" ? `${Math.round(coverage)}% check coverage` : "Coverage unavailable"}
        </span>
      </CardHeader>
      <CardContent className="space-y-3 px-4 pb-4 sm:px-5 sm:pb-5">
        {categories.length === 0 ? (
          <EmptyState compact description="Category points are not available for this scan." title="No score breakdown" />
        ) : (
          <>
            <ul className="divide-y divide-border/60">
              {categories.map((category) => (
                <li className="flex flex-wrap items-center justify-between gap-2 py-3 first:pt-0 last:pb-0" key={category.category}>
                  <div className="min-w-0">
                    <p className="text-xs font-medium text-foreground">{CATEGORY_LABELS[category.category] ?? category.category}</p>
                    <p className="mt-1 text-[10px] capitalize text-muted-foreground">{category.state} · {category.resolved_points} of {category.budget_points} points assessed</p>
                  </div>
                  <div className="text-right">
                    <p className="font-mono text-xs tabular-nums text-foreground">{category.resulting_points}<span className="text-muted-foreground">/{category.budget_points}</span></p>
                    {category.deductions > 0 && <p className="mt-1 text-[10px] text-severity-medium">−{category.deductions} points</p>}
                  </div>
                </li>
              ))}
            </ul>
            {typeof breakdown.resolved_checks === "number" && typeof breakdown.applicable_checks === "number" && (
              <p className="border-t border-border/60 pt-3 text-[10px] text-muted-foreground">
                {breakdown.resolved_checks} of {breakdown.applicable_checks} score-relevant checks resolved
                {typeof breakdown.unassessed_points === "number" ? ` · ${breakdown.unassessed_points} points unassessed` : ""}
              </p>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
