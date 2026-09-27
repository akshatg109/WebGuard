"use client";

import { useTransition } from "react";
import { LogOut, Settings2, UserRound } from "lucide-react";
import Link from "next/link";
import { signOutAction } from "@/app/auth/actions";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";

export function UserMenu({ email }: { email: string }) {
  const [isPending, startTransition] = useTransition();
  const initials = email
    .split("@")[0]
    .split(/[._-]/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("") || "WG";

  return (
    <DropdownMenu>
      <DropdownMenuTrigger aria-label={`Account menu for ${email}`} render={<Button className="h-10 gap-2 rounded-xl px-2.5" variant="ghost" />}>
        <Avatar className="size-7 rounded-lg border border-primary/20">
          <AvatarFallback className="rounded-lg bg-primary/10 text-[10px] font-semibold text-primary">{initials}</AvatarFallback>
        </Avatar>
        <span className="hidden max-w-36 truncate text-xs font-medium text-foreground sm:inline">{email}</span>
        <span aria-hidden="true" className="ml-0.5 size-1.5 rounded-full bg-severity-passed" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-64" sideOffset={8}>
        <DropdownMenuLabel className="px-2 py-2.5 font-normal">
          <span className="block truncate text-xs font-medium text-foreground">{email}</span>
          <span className="mt-1 block text-[11px] text-muted-foreground">Authenticated account</span>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem render={<Link href="/settings" />}>
          <UserRound aria-hidden="true" />Account settings
        </DropdownMenuItem>
        <DropdownMenuItem render={<Link href="/settings#security" />}>
          <Settings2 aria-hidden="true" />Security & session
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem disabled={isPending} onClick={() => startTransition(async () => signOutAction())} variant="destructive">
          <LogOut aria-hidden="true" />{isPending ? "Signing out…" : "Sign out"}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
