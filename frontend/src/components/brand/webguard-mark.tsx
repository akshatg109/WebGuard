import { ShieldCheck } from "lucide-react";
import Link from "next/link";
import { cn } from "@/lib/utils";

export function WebGuardMark({
  href = "/dashboard",
  compact = false,
  className,
}: {
  href?: string;
  compact?: boolean;
  className?: string;
}) {
  return (
    <Link
      aria-label="WebGuard home"
      className={cn(
        "group inline-flex w-fit items-center gap-3 rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background",
        className,
      )}
      href={href}
    >
      <span className="grid size-9 place-items-center rounded-xl border border-primary/25 bg-primary/10 text-primary shadow-[0_0_22px_-10px_var(--primary)]">
        <ShieldCheck aria-hidden="true" className="size-[18px]" strokeWidth={2.1} />
      </span>
      {!compact && (
        <span className="flex flex-col leading-none">
          <span className="text-[15px] font-semibold tracking-[-0.035em] text-foreground">WebGuard</span>
          <span className="mt-1.5 text-[9px] font-semibold tracking-[0.18em] text-muted-foreground uppercase">
            Security observability
          </span>
        </span>
      )}
    </Link>
  );
}
