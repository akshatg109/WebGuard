import { ShieldCheck } from "lucide-react";

export function DemoBanner() {
  return (
    <aside className="flex items-start gap-2.5 rounded-lg border border-primary/20 bg-primary/[0.045] px-3.5 py-3 text-xs sm:items-center">
      <ShieldCheck aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-primary sm:mt-0" />
      <p className="leading-5 text-muted-foreground">
        <span className="font-semibold tracking-wide text-primary">AUTHENTICATED SCANNER</span>
        <span aria-hidden="true"> · </span>
        Scan results come from the private API; only assess websites you own or are explicitly authorized to test. A score is not proof of security.
      </p>
    </aside>
  );
}
