import type { LucideIcon } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

export function MetricCard({
  label,
  icon: Icon,
  tone,
  value,
  detail,
}: {
  label: string;
  icon: LucideIcon;
  tone: "critical" | "high" | "medium" | "low" | "neutral";
  value: string;
  detail: string;
}) {
  const toneClasses = {
    critical: "text-severity-critical",
    high: "text-severity-high",
    medium: "text-severity-medium",
    low: "text-severity-low",
    neutral: "text-muted-foreground",
  } as const;
  const color = toneClasses[tone];

  return (
    <Card className="min-w-0 border-border/70 bg-card/80 shadow-none">
      <CardContent className="flex items-center gap-3.5 px-4 py-4 sm:px-5">
        <span className={`grid size-9 shrink-0 place-items-center rounded-lg border border-current/15 bg-current/5 ${color}`}>
          <Icon aria-hidden="true" className="size-4" strokeWidth={1.8} />
        </span>
        <div className="min-w-0">
          <p className="text-[11px] font-medium text-muted-foreground">{label}</p>
          <p className="mt-1 text-xl leading-none font-semibold tabular-nums tracking-tight text-foreground">{value}</p>
          <p className="mt-1.5 text-[10px] text-muted-foreground/80">{detail}</p>
        </div>
      </CardContent>
    </Card>
  );
}
