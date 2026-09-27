"use client";

import { useTransition } from "react";
import { LogOut, LoaderCircle } from "lucide-react";
import { signOutAction } from "@/app/auth/actions";
import { Button } from "@/components/ui/button";

export function SignOutButton() {
  const [isPending, startTransition] = useTransition();
  return (
    <Button disabled={isPending} onClick={() => startTransition(async () => signOutAction())} variant="outline">
      {isPending ? <LoaderCircle aria-hidden="true" className="size-4 animate-spin" /> : <LogOut aria-hidden="true" className="size-4" />}
      {isPending ? "Signing out…" : "Sign out"}
    </Button>
  );
}
