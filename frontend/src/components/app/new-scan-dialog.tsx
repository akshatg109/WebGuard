"use client";

import { ArrowRight, ScanLine, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";

export function NewScanDialog() {
  return (
    <Dialog>
      <DialogTrigger render={<Button className="h-10 gap-2 px-4" />}>
        <ScanLine aria-hidden="true" className="size-4" />
        New scan
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <span className="mb-1 grid size-10 place-items-center rounded-xl border border-primary/20 bg-primary/10 text-primary">
            <ShieldAlert aria-hidden="true" className="size-5" />
          </span>
          <DialogTitle>Scanning is not connected yet</DialogTitle>
          <DialogDescription className="leading-6">
            This workspace preview does not send requests to targets or create scan records. Scanner capabilities are scheduled for a later phase.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button render={<Link href="/scans" />} variant="outline">
            View scan history <ArrowRight aria-hidden="true" className="size-4" />
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
