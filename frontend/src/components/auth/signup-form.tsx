"use client";

import { useState, useTransition } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { Check, LoaderCircle, MailCheck } from "lucide-react";
import { useForm, type UseFormRegisterReturn } from "react-hook-form";
import { z } from "zod";
import { signUpAction } from "@/app/auth/actions";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const signUpSchema = z
  .object({
    email: z.string().trim().email("Enter a valid email address."),
    password: z
      .string()
      .min(8, "Use at least 8 characters.")
      .max(128, "Use no more than 128 characters."),
    confirmPassword: z.string(),
  })
  .refine((values) => values.password === values.confirmPassword, {
    message: "Passwords do not match.",
    path: ["confirmPassword"],
  });

type SignUpValues = z.infer<typeof signUpSchema>;

export function SignupForm() {
  const [isPending, startTransition] = useTransition();
  const [submitted, setSubmitted] = useState(false);
  const [requestError, setRequestError] = useState<string | null>(null);
  const form = useForm<SignUpValues>({
    resolver: zodResolver(signUpSchema),
    defaultValues: { email: "", password: "", confirmPassword: "" },
  });

  function onSubmit(values: SignUpValues) {
    setRequestError(null);
    startTransition(async () => {
      const formData = new FormData();
      formData.set("email", values.email);
      formData.set("password", values.password);

      try {
        const result = await signUpAction(formData);
        if (result.status === "error") {
          setRequestError(result.message);
          return;
        }
        setSubmitted(true);
      } catch {
        setRequestError("Signup could not be completed. Please try again.");
      }
    });
  }

  if (submitted) {
    return (
      <section aria-live="polite" className="rounded-2xl border border-primary/20 bg-primary/[0.045] p-6 text-center" role="status">
        <span className="mx-auto grid size-12 place-items-center rounded-2xl border border-primary/20 bg-primary/10 text-primary">
          <MailCheck aria-hidden="true" className="size-6" />
        </span>
        <h3 className="mt-4 text-lg font-semibold tracking-tight">Check your inbox</h3>
        <p className="mx-auto mt-2 max-w-sm text-sm leading-6 text-muted-foreground">
          If signup can proceed, the next steps have been sent to that email address. Follow the confirmation link to activate your account.
        </p>
        <ul className="mt-5 space-y-2 text-left text-xs text-muted-foreground">
          <li className="flex items-center gap-2"><Check aria-hidden="true" className="size-3.5 text-primary" /> Check your inbox and spam folder</li>
          <li className="flex items-center gap-2"><Check aria-hidden="true" className="size-3.5 text-primary" /> Confirmation links expire for your protection</li>
        </ul>
      </section>
    );
  }

  return (
    <form className="space-y-4" noValidate onSubmit={form.handleSubmit(onSubmit)}>
      {requestError && (
        <Alert variant="destructive">
          <AlertTitle>Unable to create account</AlertTitle>
          <AlertDescription>{requestError}</AlertDescription>
        </Alert>
      )}

      <AuthField
        autoComplete="email"
        error={form.formState.errors.email?.message}
        id="signup-email"
        label="Email address"
        placeholder="you@company.com"
        register={form.register("email")}
        type="email"
      />
      <AuthField
        autoComplete="new-password"
        error={form.formState.errors.password?.message}
        id="signup-password"
        label="Password"
        placeholder="At least 8 characters"
        register={form.register("password")}
        type="password"
      />
      <AuthField
        autoComplete="new-password"
        error={form.formState.errors.confirmPassword?.message}
        id="signup-confirm-password"
        label="Confirm password"
        placeholder="Enter your password again"
        register={form.register("confirmPassword")}
        type="password"
      />

      <p className="rounded-lg border border-border/70 bg-muted/30 px-3 py-2.5 text-xs leading-5 text-muted-foreground">
        Use at least 8 characters. Email confirmation is required before your first sign in.
      </p>

      <Button className="h-11 w-full text-sm font-semibold" disabled={isPending} type="submit">
        {isPending ? (
          <><LoaderCircle aria-hidden="true" className="size-4 animate-spin" /> Creating account…</>
        ) : (
          "Create account"
        )}
      </Button>
      <p aria-live="polite" className="sr-only" role="status">{isPending ? "Creating account" : ""}</p>
    </form>
  );
}

function AuthField({
  autoComplete,
  error,
  id,
  label,
  placeholder,
  register,
  type,
}: {
  autoComplete: string;
  error?: string;
  id: string;
  label: string;
  placeholder: string;
  register: UseFormRegisterReturn;
  type: "email" | "password";
}) {
  const errorId = `${id}-error`;

  return (
    <div className="space-y-2">
      <Label htmlFor={id}>{label}</Label>
      <Input
        {...register}
        autoComplete={autoComplete}
        aria-describedby={error ? errorId : undefined}
        aria-invalid={Boolean(error)}
        className="h-11"
        id={id}
        placeholder={placeholder}
        type={type}
      />
      {error && <p className="text-xs text-destructive" id={errorId} role="alert">{error}</p>}
    </div>
  );
}
