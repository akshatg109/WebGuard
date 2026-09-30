import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { CheckStatus, ScanStatus as ApiScanStatus } from "@/lib/scanner/types";

export type ScanStatus = ApiScanStatus | CheckStatus | "not-run" | "preview";

const config: Record<ScanStatus, { label: string; className: string; marker: string }> = {
  pending: { label: "Pending", className: "border-border bg-muted/50 text-muted-foreground", marker: "bg-muted-foreground/60" },
  completed: { label: "Completed", className: "border-severity-passed/25 bg-severity-passed/10 text-severity-passed", marker: "bg-severity-passed" },
  running: { label: "Running", className: "border-primary/25 bg-primary/10 text-primary", marker: "bg-primary animate-pulse" },
  failed: { label: "Failed", className: "border-severity-critical/25 bg-severity-critical/10 text-severity-critical", marker: "bg-severity-critical" },
  pass: { label: "Pass", className: "border-severity-passed/25 bg-severity-passed/10 text-severity-passed", marker: "bg-severity-passed" },
  fail: { label: "Fail", className: "border-severity-critical/25 bg-severity-critical/10 text-severity-critical", marker: "bg-severity-critical" },
  warn: { label: "Review", className: "border-severity-medium/25 bg-severity-medium/10 text-severity-medium", marker: "bg-severity-medium" },
  not_applicable: { label: "Not applicable", className: "border-border bg-muted/50 text-muted-foreground", marker: "bg-muted-foreground/60" },
  error: { label: "Unable to assess", className: "border-severity-high/25 bg-severity-high/10 text-severity-high", marker: "bg-severity-high" },
  "not-run": { label: "Not run", className: "border-border bg-muted/50 text-muted-foreground", marker: "bg-muted-foreground/60" },
  preview: { label: "Preview", className: "border-primary/25 bg-primary/10 text-primary", marker: "bg-primary" },
};

export function ScanStatusBadge({ status, className }: { status: ScanStatus; className?: string }) {
  const item = config[status];
  return (
    <Badge className={cn("gap-1.5 border px-2 py-1 text-[10px] font-medium", item.className, className)} variant="outline">
      <span aria-hidden="true" className={cn("size-1.5 rounded-full", item.marker)} />
      {item.label}
    </Badge>
  );
}
