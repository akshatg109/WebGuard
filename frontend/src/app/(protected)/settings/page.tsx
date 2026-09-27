import { KeyRound, ShieldCheck, UserRound } from "lucide-react";
import { PageHeader } from "@/components/shared/page-header";
import { SettingsSection } from "@/components/settings/settings-section";
import { SignOutButton } from "@/components/settings/sign-out-button";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { requireUser } from "@/lib/supabase/require-user";

export default async function SettingsPage() {
  const user = await requireUser();
  const initials = user.email === "Authenticated account"
    ? "WG"
    : user.email.slice(0, 1).toUpperCase();

  return (
    <div className="space-y-7">
      <PageHeader
        description="Manage your account details and review the current session security context."
        eyebrow="WORKSPACE PREFERENCES"
        title="Settings"
      />
      <div className="grid items-start gap-6 lg:grid-cols-[190px_minmax(0,1fr)]">
        <nav aria-label="Settings sections" className="flex gap-1 overflow-x-auto rounded-lg border border-border/60 bg-card/40 p-1 lg:sticky lg:top-24 lg:flex-col lg:border-0 lg:bg-transparent lg:p-0">
          <a className="whitespace-nowrap rounded-md bg-muted px-3 py-2 text-xs font-medium text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" href="#profile" aria-current="location">Profile</a>
          <a className="whitespace-nowrap rounded-md px-3 py-2 text-xs text-muted-foreground hover:bg-muted/60 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" href="#security">Security</a>
        </nav>

        <div className="min-w-0 space-y-4">
          <SettingsSection
            description="Your authenticated account details. Profile editing is not available in this preview."
            icon={UserRound}
            id="profile"
            title="Profile"
          >
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
              <Avatar className="size-12 rounded-xl border border-primary/20">
                <AvatarFallback className="rounded-xl bg-primary/10 text-sm font-semibold text-primary">{initials}</AvatarFallback>
              </Avatar>
              <div className="min-w-0">
                <p className="text-[10px] font-semibold tracking-[0.12em] text-muted-foreground uppercase">Email address</p>
                <p className="mt-1 break-all text-sm font-medium text-foreground">{user.email}</p>
                <p className="mt-1 text-[11px] text-muted-foreground">Managed by Supabase Auth</p>
              </div>
              <Badge className="w-fit gap-1.5 border-severity-passed/25 bg-severity-passed/10 text-[10px] text-severity-passed sm:ml-auto" variant="outline">
                <span aria-hidden="true" className="size-1.5 rounded-full bg-current" /> Authenticated
              </Badge>
            </div>
            <div className="mt-5 grid gap-3 border-t border-border/60 pt-4 sm:grid-cols-2">
              <AccountValue label="Account ID" value={maskId(user.id)} />
              <AccountValue label="Workspace" value="Personal" />
            </div>
          </SettingsSection>

          <SettingsSection
            description="Your session is verified on the server and refreshed with secure cookies."
            icon={KeyRound}
            id="security"
            title="Security & session"
          >
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
              <div className="flex items-start gap-3">
                <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-severity-passed/10 text-severity-passed">
                  <ShieldCheck aria-hidden="true" className="size-4" />
                </span>
                <div>
                  <p className="text-xs font-medium text-foreground">Authenticated session active</p>
                  <p className="mt-1 max-w-md text-[11px] leading-5 text-muted-foreground">
                    WebGuard validates session claims before rendering protected pages. Signing out clears the local session.
                  </p>
                </div>
              </div>
              <div className="sm:ml-auto"><SignOutButton /></div>
            </div>
          </SettingsSection>

          <Card className="border-border/60 bg-background/20 p-4 text-xs leading-5 text-muted-foreground sm:p-5">
            Settings are limited to account and session details during the UI preview. No profile changes or account deletions are available here.
          </Card>
        </div>
      </div>
    </div>
  );
}

function AccountValue({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-border/60 bg-background/25 px-3 py-2.5">
      <p className="text-[10px] font-semibold tracking-[0.12em] text-muted-foreground uppercase">{label}</p>
      <p className="mt-1 break-all font-mono text-xs text-foreground/85">{value}</p>
    </div>
  );
}

function maskId(id: string) {
  return id.length > 12 ? `${id.slice(0, 8)}…${id.slice(-4)}` : id;
}
