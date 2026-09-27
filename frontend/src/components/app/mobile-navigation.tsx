"use client";

import { useState } from "react";
import { Menu } from "lucide-react";
import { WebGuardMark } from "@/components/brand/webguard-mark";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { SidebarFooter, SidebarNavigation } from "@/components/app/sidebar";

export function MobileNavigation() {
  const [open, setOpen] = useState(false);

  return (
    <Sheet onOpenChange={setOpen} open={open}>
      <SheetTrigger aria-label="Open navigation menu" render={<Button className="lg:hidden" size="icon" variant="ghost" />}>
        <Menu aria-hidden="true" />
      </SheetTrigger>
      <SheetContent aria-describedby="mobile-nav-description" className="border-sidebar-border bg-sidebar p-0" side="left">
        <SheetHeader className="border-b border-sidebar-border px-5 py-5 text-left">
          <WebGuardMark href="/dashboard" />
          <SheetTitle className="sr-only">WebGuard navigation</SheetTitle>
          <SheetDescription className="sr-only" id="mobile-nav-description">
            Navigate to your dashboard, scan history, or settings.
          </SheetDescription>
        </SheetHeader>
        <div className="flex min-h-0 flex-1 flex-col justify-between p-4">
          <SidebarNavigation onNavigate={() => setOpen(false)} />
          <SidebarFooter />
        </div>
      </SheetContent>
    </Sheet>
  );
}
