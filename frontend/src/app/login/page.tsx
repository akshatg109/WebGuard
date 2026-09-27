import Link from "next/link";
import { redirect } from "next/navigation";
import { AuthConfigNotice } from "@/components/auth/auth-config-notice";
import { AuthShell } from "@/components/auth/auth-shell";
import { LoginForm } from "@/components/auth/login-form";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { hasSupabasePublicConfig } from "@/lib/supabase/config";
import { createClient } from "@/lib/supabase/server";

export const dynamic = "force-dynamic";

type LoginPageProps = {
  searchParams: Promise<{ error?: string | string[]; next?: string | string[] }>;
};

export default async function LoginPage({ searchParams }: LoginPageProps) {
  const query = await searchParams;
  const redirectTo = safeInternalPath(query.next);
  const errorCode = firstValue(query.error);

  if (hasSupabasePublicConfig()) {
    let isAuthenticated = false;
    try {
      const supabase = await createClient();
      const { data } = await supabase.auth.getClaims();
      isAuthenticated = Boolean(data?.claims?.sub);
    } catch {
      // Keep the login page available; the submit action provides a generic error.
    }
    if (isAuthenticated) redirect(redirectTo);
  }

  return (
    <AuthShell
      description="Sign in to review your authorized security assessments."
      footer={
        <>
          New to WebGuard?{" "}
          <Link className="font-semibold text-primary underline-offset-4 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" href="/signup">
            Create an account
          </Link>
        </>
      }
      title="Welcome back"
    >
      {errorCode === "confirmation_failed" && (
        <Alert className="mb-5 border-severity-medium/30 bg-severity-medium/5 text-foreground">
          <AlertDescription>
            That confirmation link is invalid or has expired. Sign up again to request a fresh link.
          </AlertDescription>
        </Alert>
      )}
      {errorCode === "auth_unavailable" && (
        <Alert className="mb-5 border-severity-medium/30 bg-severity-medium/5 text-foreground">
          <AlertDescription>Authentication is not configured yet. Add the public Supabase project values to enable sign in.</AlertDescription>
        </Alert>
      )}
      {hasSupabasePublicConfig() ? <LoginForm redirectTo={redirectTo} /> : <AuthConfigNotice />}
      <p className="mt-5 text-center text-[11px] leading-5 text-muted-foreground">
        Your session is managed with secure, server-set authentication cookies.
      </p>
    </AuthShell>
  );
}

function firstValue(value?: string | string[]) {
  return Array.isArray(value) ? value[0] : value;
}

function safeInternalPath(value?: string | string[]) {
  const path = firstValue(value);
  if (!path || !path.startsWith("/") || path.startsWith("//") || path.includes("\\")) {
    return "/dashboard";
  }
  return path;
}
