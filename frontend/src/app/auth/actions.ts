"use server";

import { redirect } from "next/navigation";
import { z } from "zod";
import { createClient } from "@/lib/supabase/server";

const credentialsSchema = z.object({
  email: z.string().trim().email("Enter a valid email address."),
  password: z.string().min(8, "Password must be at least 8 characters.").max(128),
});

function parseCredentials(formData: FormData) {
  return credentialsSchema.safeParse({
    email: formData.get("email"),
    password: formData.get("password"),
  });
}

export async function signUpAction(formData: FormData) {
  const parsed = parseCredentials(formData);
  if (!parsed.success) {
    return { status: "error" as const, message: parsed.error.issues[0]?.message ?? "Check your details." };
  }

  const supabase = await createClient();
  const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "http://localhost:3000";
  // Use one response for success and failure to avoid email account enumeration.
  const { error } = await supabase.auth.signUp({
    ...parsed.data,
    options: { emailRedirectTo: new URL("/auth/confirm", siteUrl).toString() },
  });

  if (error?.code === "weak_password") {
    return {
      status: "error" as const,
      message: "Choose a stronger password that meets the project’s password rules.",
    };
  }

  if (error) {
    if (error.code === "user_already_exists" || error.code === "email_exists") {
      // Keep duplicate-account responses indistinguishable from successful signup.
      return genericSignupSuccess();
    }

    return {
      status: "error" as const,
      message: isTransientAuthFailure(error)
        ? "Signup is temporarily unavailable. Please try again shortly."
        : "We couldn’t process signup. Check your details or try again.",
    };
  }

  return genericSignupSuccess();
}

function genericSignupSuccess() {
  return {
    status: "success" as const,
    message: "If signup can proceed, you will receive the next steps by email.",
  };
}

function isTransientAuthFailure(error: { name?: string; status?: number }) {
  return (
    error.name === "AuthRetryableFetchError" ||
    error.status === undefined ||
    error.status === 429 ||
    error.status >= 500
  );
}

export async function signInAction(formData: FormData) {
  const parsed = parseCredentials(formData);
  if (!parsed.success) {
    return { status: "error" as const, message: parsed.error.issues[0]?.message ?? "Check your details." };
  }

  const supabase = await createClient();
  const { error } = await supabase.auth.signInWithPassword(parsed.data);

  if (error) {
    if (isTransientAuthFailure(error)) {
      return {
        status: "error" as const,
        message: "Sign in is temporarily unavailable. Please try again shortly.",
      };
    }
    return { status: "error" as const, message: "Email or password is incorrect." };
  }

  return { status: "success" as const };
}

export async function signOutAction() {
  const supabase = await createClient();
  await supabase.auth.signOut();
  redirect("/login");
}
