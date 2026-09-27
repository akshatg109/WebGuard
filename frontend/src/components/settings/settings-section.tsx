import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function SettingsSection({
  id,
  title,
  description,
  icon: Icon,
  children,
}: {
  id?: string;
  title: string;
  description: string;
  icon: LucideIcon;
  children: ReactNode;
}) {
  return (
    <Card className="scroll-mt-24 border-border/70 bg-card/80 shadow-none" id={id}>
      <CardHeader className="flex-row items-start gap-3 border-b border-border/60 pb-4">
        <span className="grid size-9 shrink-0 place-items-center rounded-lg border border-border/70 bg-muted/40 text-muted-foreground">
          <Icon aria-hidden="true" className="size-4" />
        </span>
        <div>
          <CardTitle className="text-sm">{title}</CardTitle>
          <p className="mt-1 text-xs leading-5 text-muted-foreground">{description}</p>
        </div>
      </CardHeader>
      <CardContent className="p-4 sm:p-5">{children}</CardContent>
    </Card>
  );
}
