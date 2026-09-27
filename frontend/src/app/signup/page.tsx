import Link from "next/link";
import { redirect } from "next/navigation";
import { AuthConfigNotice } from "@/components/auth/auth-config-notice";
import { AuthShell } from "@/components/auth/auth-shell";
import { SignupForm } from "@/components/auth/signup-form";
import { hasSupabasePublicConfig } from "@/lib/supabase/config";
import { createClient } from "@/lib/supabase/server";

export const dynamic = "force-dynamic";

export default async function SignupPage() {
  if (hasSupabasePublicConfig()) {
    let isAuthenticated = false;
    try {
      const supabase = await createClient();
      const { data } = await supabase.auth.getClaims();
      isAuthenticated = Boolean(data?.claims?.sub);
    } catch {
      // Keep account creation available; submission errors remain generic.
    }
    if (isAuthenticated) redirect("/dashboard");
  }

  return (
    <AuthShell
      description="Create a personal workspace for authorized website security reviews."
      footer={
        <>
          Already have an account?{" "}
          <Link className="font-semibold text-primary underline-offset-4 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" href="/login">
            Sign in
          </Link>
        </>
      }
      title="Create your account"
    >
      {hasSupabasePublicConfig() ? <SignupForm /> : <AuthConfigNotice />}
      <p className="mt-5 text-center text-[11px] leading-5 text-muted-foreground">
        Email confirmation is required. We never reveal whether an email is already registered.
      </p>
    </AuthShell>
  );
}
