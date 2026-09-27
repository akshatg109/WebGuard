import type { ReactNode } from "react";
import { WebGuardMark } from "@/components/brand/webguard-mark";
import { Breadcrumbs } from "@/components/app/breadcrumbs";
import { DemoBanner } from "@/components/app/demo-banner";
import { MobileNavigation } from "@/components/app/mobile-navigation";
import { SidebarFooter, SidebarNavigation } from "@/components/app/sidebar";
import { UserMenu } from "@/components/app/user-menu";

export function AppShell({
  children,
  user,
}: {
  children: ReactNode;
  user: { id: string; email: string };
}) {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <a className="sr-only z-[100] rounded-md bg-primary px-4 py-2 font-medium text-primary-foreground focus:not-sr-only focus:fixed focus:top-3 focus:left-3" href="#main-content">
        Skip to content
      </a>
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-[252px] flex-col border-r border-sidebar-border bg-sidebar px-4 py-5 lg:flex">
        <div className="px-2 pb-7"><WebGuardMark /></div>
        <div className="px-2 pb-3 text-[10px] font-semibold tracking-[0.16em] text-muted-foreground/75 uppercase">Workspace</div>
        <SidebarNavigation />
        <div className="mt-auto space-y-5 px-1"><SidebarFooter /></div>
      </aside>

      <div className="flex min-h-screen min-w-0 flex-col lg:pl-[252px]">
        <header className="sticky top-0 z-20 flex h-[68px] items-center justify-between border-b border-border/70 bg-background/90 px-4 backdrop-blur-xl sm:px-6 xl:px-9">
          <div className="flex min-w-0 items-center gap-3">
            <MobileNavigation />
            <Breadcrumbs />
          </div>
          <UserMenu email={user.email} />
        </header>
        <main className="mx-auto flex w-full max-w-[1560px] min-w-0 flex-1 flex-col gap-6 px-4 py-6 sm:px-6 sm:py-8 xl:px-9" id="main-content">
          <DemoBanner />
          {children}
          <footer className="mt-auto flex flex-col gap-2 border-t border-border/60 pt-5 text-[11px] text-muted-foreground sm:flex-row sm:items-center sm:justify-between">
            <span>WebGuard · Defensive configuration review</span>
            <span>Only assess websites you own or are authorized to test.</span>
          </footer>
        </main>
      </div>
    </div>
  );
}
