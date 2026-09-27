import type { ReactNode } from "react";
import { Activity, ArrowUpRight, LockKeyhole, ScanSearch } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { WebGuardMark } from "@/components/brand/webguard-mark";

export function AuthShell({
  children,
  title,
  description,
  footer,
}: {
  children: ReactNode;
  title: string;
  description: string;
  footer: ReactNode;
}) {
  return (
    <main className="min-h-screen bg-background lg:grid lg:grid-cols-[minmax(400px,0.92fr)_1.08fr]">
      <section className="relative hidden min-h-screen flex-col justify-between overflow-hidden border-r border-border/70 bg-sidebar px-12 py-10 lg:flex xl:px-16">
        <div className="pointer-events-none absolute inset-0 opacity-45 [background-image:linear-gradient(to_right,oklch(1_0_0_/_0.035)_1px,transparent_1px),linear-gradient(to_bottom,oklch(1_0_0_/_0.035)_1px,transparent_1px)] [background-size:56px_56px]" />
        <div className="pointer-events-none absolute -top-48 -left-28 size-[420px] rounded-full bg-primary/10 blur-[110px]" />
        <div className="relative z-10"><WebGuardMark href="/login" /></div>

        <div className="relative z-10 -mt-16 max-w-xl">
          <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/5 px-3 py-1.5 text-[11px] font-medium tracking-wide text-primary">
            <span className="size-1.5 rounded-full bg-primary" />
            BUILT FOR DEFENSIVE SECURITY
          </div>
          <h1 className="max-w-lg text-[clamp(2.6rem,4.2vw,4.4rem)] leading-[1.03] font-medium tracking-[-0.065em] text-foreground">
            Make your web security posture clear.
          </h1>
          <p className="mt-6 max-w-md text-[15px] leading-7 text-muted-foreground">
            A focused workspace for reviewing the security configuration of websites you own or are authorized to assess.
          </p>
          <div className="mt-12 grid gap-3 sm:grid-cols-3 lg:grid-cols-1 xl:grid-cols-3">
            <FeatureNote icon={ScanSearch} title="Passive checks" detail="Configuration first" />
            <FeatureNote icon={LockKeyhole} title="Private by design" detail="Your scans stay yours" />
            <FeatureNote icon={Activity} title="Clear next steps" detail="Findings to guidance" />
          </div>
        </div>

        <div className="relative z-10 flex items-center justify-between text-xs text-muted-foreground">
          <span>WebGuard · Authorized testing only</span>
          <a
            className="inline-flex items-center gap-1 rounded-sm hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            href="https://owasp.org/www-project-secure-headers/"
            rel="noreferrer"
            target="_blank"
          >
            Security reference <ArrowUpRight aria-hidden="true" className="size-3" />
          </a>
        </div>
      </section>

      <section className="flex min-h-screen flex-col px-5 py-6 sm:px-10 lg:px-14">
        <div className="flex items-center justify-between lg:justify-end">
          <WebGuardMark className="lg:hidden" href="/login" />
          <span className="rounded-full border border-border/80 bg-card/60 px-3 py-1.5 text-[10px] font-semibold tracking-[0.12em] text-muted-foreground uppercase">
            Secure access
          </span>
        </div>
        <div className="my-auto flex w-full justify-center py-10">
          <div className="w-full max-w-[420px]">
            <div className="mb-8">
              <p className="mb-3 text-xs font-semibold tracking-[0.17em] text-primary uppercase">WebGuard workspace</p>
              <h2 className="text-3xl font-semibold tracking-[-0.045em] text-foreground">{title}</h2>
              <p className="mt-2 text-sm leading-6 text-muted-foreground">{description}</p>
            </div>
            {children}
            <div className="mt-6 text-center text-sm text-muted-foreground">{footer}</div>
          </div>
        </div>
        <p className="text-center text-[11px] leading-5 text-muted-foreground/80">
          By continuing, you agree to use WebGuard only on systems you own or have permission to assess.
        </p>
      </section>
    </main>
  );
}

function FeatureNote({ icon: Icon, title, detail }: { icon: LucideIcon; title: string; detail: string }) {
  return (
    <div className="flex items-center gap-3 rounded-xl border border-border/70 bg-background/45 px-3.5 py-3 backdrop-blur-sm">
      <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-primary/10 text-primary">
        <Icon aria-hidden="true" className="size-4" />
      </span>
      <span className="min-w-0">
        <span className="block text-xs font-medium text-foreground">{title}</span>
        <span className="mt-0.5 block text-[10px] text-muted-foreground">{detail}</span>
      </span>
    </div>
  );
}
