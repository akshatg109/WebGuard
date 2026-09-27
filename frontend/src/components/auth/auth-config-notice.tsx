import { AlertTriangle, KeyRound } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

export function AuthConfigNotice() {
  return (
    <Alert className="border-severity-medium/30 bg-severity-medium/5 [&>svg]:text-severity-medium">
      <AlertTriangle aria-hidden="true" />
      <AlertTitle>Authentication needs project configuration</AlertTitle>
      <AlertDescription className="mt-1 leading-6">
        Add <code className="rounded bg-muted px-1 py-0.5 text-xs">NEXT_PUBLIC_SUPABASE_URL</code> and{" "}
        <code className="rounded bg-muted px-1 py-0.5 text-xs">NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY</code>{" "}
        to <code className="rounded bg-muted px-1 py-0.5 text-xs">frontend/.env.local</code>, then restart Next.js.
        Keep the Supabase secret key on the server only.
        <span className="mt-2 flex items-center gap-1.5 text-xs text-muted-foreground">
          <KeyRound aria-hidden="true" className="size-3.5" /> No authentication is bypassed in preview mode.
        </span>
      </AlertDescription>
    </Alert>
  );
}
