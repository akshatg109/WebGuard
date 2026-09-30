import { Cookie, FileCheck2, Globe2, LockKeyhole } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const checkGroups = [
  { label: "Transport security", detail: "HTTPS · redirects · TLS", icon: LockKeyhole },
  { label: "Security headers", detail: "HSTS · CSP · browser policy", icon: FileCheck2 },
  { label: "Cookie attributes", detail: "Secure · HttpOnly · SameSite", icon: Cookie },
  { label: "Response exposure", detail: "Server details · mixed content", icon: Globe2 },
];

export function CheckCoverage() {
  return (
    <Card className="border-border/70 bg-card/80 shadow-none">
      <CardHeader>
          <p className="text-[10px] font-semibold tracking-[0.16em] text-muted-foreground uppercase">Scanner scope</p>
        <CardTitle className="mt-1.5 text-base">What WebGuard reviews</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-2 px-4 pb-4 sm:grid-cols-2 sm:px-5 sm:pb-5">
        {checkGroups.map(({ label, detail, icon: Icon }) => (
          <div className="flex min-w-0 items-center gap-3 rounded-lg border border-border/60 bg-background/25 p-3" key={label}>
            <span className="grid size-8 shrink-0 place-items-center rounded-lg border border-border/60 bg-muted/45 text-muted-foreground">
              <Icon aria-hidden="true" className="size-4" />
            </span>
            <div className="min-w-0 flex-1">
              <p className="truncate text-xs font-medium text-foreground">{label}</p>
              <p className="mt-1 truncate text-[10px] text-muted-foreground">{detail}</p>
            </div>
            <span className="shrink-0 rounded-md border border-border/70 bg-muted/30 px-2 py-1 text-[10px] text-muted-foreground">Passive</span>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
