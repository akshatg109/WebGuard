import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const severityStyles = cva(
  "inline-flex min-h-6 items-center gap-1.5 rounded-md border px-2 py-0.5 text-[10px] font-semibold tracking-wide",
  {
    variants: {
      severity: {
        critical: "border-severity-critical/25 bg-severity-critical/10 text-severity-critical",
        high: "border-severity-high/25 bg-severity-high/10 text-severity-high",
        medium: "border-severity-medium/25 bg-severity-medium/10 text-severity-medium",
        low: "border-severity-low/25 bg-severity-low/10 text-severity-low",
        informational: "border-severity-informational/25 bg-severity-informational/10 text-severity-informational",
        passed: "border-severity-passed/25 bg-severity-passed/10 text-severity-passed",
      },
    },
  },
);

export type Severity = NonNullable<VariantProps<typeof severityStyles>["severity"]>;

const severityLabels: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Informational",
  passed: "Passed",
};

export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity;
  className?: string;
}) {
  return (
    <span className={cn(severityStyles({ severity }), className)}>
      <span aria-hidden="true" className="size-1.5 rounded-full bg-current" />
      {severityLabels[severity]}
    </span>
  );
}
