import { CircleDashed } from "lucide-react";
import { ScanStatusBadge } from "@/components/shared/scan-status-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const plannedChecks = [
  "HTTPS usage",
  "HTTP to HTTPS redirect",
  "HTTP Strict Transport Security",
  "Content Security Policy",
  "X-Content-Type-Options",
  "Referrer Policy",
  "Permissions Policy",
  "Frame protection",
  "Cookie security attributes",
  "Server information exposure",
  "Mixed content indicators",
];

export function SecurityCheckList() {
  return (
    <Card className="border-border/70 bg-card/80 shadow-none">
      <CardHeader className="flex-row items-center justify-between gap-3">
        <div>
          <p className="text-[10px] font-semibold tracking-[0.16em] text-muted-foreground uppercase">Check catalog</p>
          <CardTitle className="mt-1.5 text-base">Security checks</CardTitle>
        </div>
        <span className="text-[10px] text-muted-foreground">{plannedChecks.length} planned</span>
      </CardHeader>
      <CardContent className="px-4 pb-4 sm:px-5 sm:pb-5">
        <ul className="divide-y divide-border/60">
          {plannedChecks.map((check) => (
            <li className="flex items-center justify-between gap-3 py-3 first:pt-0 last:pb-0" key={check}>
              <span className="flex min-w-0 items-center gap-2.5 text-xs text-foreground/90">
                <CircleDashed aria-hidden="true" className="size-3.5 shrink-0 text-muted-foreground" />
                <span className="truncate">{check}</span>
              </span>
              <ScanStatusBadge status="not-run" />
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
