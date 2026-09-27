import type { ReactNode } from "react";
import { Inbox } from "lucide-react";

export function EmptyState({
  title,
  description,
  action,
  compact = false,
}: {
  title: string;
  description: string;
  action?: ReactNode;
  compact?: boolean;
}) {
  return (
    <div className={`flex flex-col items-center justify-center rounded-xl border border-dashed border-border/90 bg-background/25 px-5 text-center ${compact ? "py-8" : "py-12 sm:py-16"}`}>
      <span className="grid size-11 place-items-center rounded-2xl border border-border/70 bg-muted/55 text-muted-foreground">
        <Inbox aria-hidden="true" className="size-5" />
      </span>
      <h3 className="mt-4 text-sm font-semibold text-foreground">{title}</h3>
      <p className="mt-1.5 max-w-md text-xs leading-5 text-muted-foreground">{description}</p>
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}
