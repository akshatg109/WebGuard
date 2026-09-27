"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { zodResolver } from "@hookform/resolvers/zod";
import { LoaderCircle, Mail } from "lucide-react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { signInAction } from "@/app/auth/actions";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const signInSchema = z.object({
  email: z.string().trim().email("Enter a valid email address."),
  password: z.string().min(8, "Password must be at least 8 characters."),
});

type SignInValues = z.infer<typeof signInSchema>;

export function LoginForm({ redirectTo }: { redirectTo: string }) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const [requestError, setRequestError] = useState<string | null>(null);
  const form = useForm<SignInValues>({
    resolver: zodResolver(signInSchema),
    defaultValues: { email: "", password: "" },
  });

  function onSubmit(values: SignInValues) {
    setRequestError(null);
    startTransition(async () => {
      const formData = new FormData();
      formData.set("email", values.email);
      formData.set("password", values.password);

      try {
        const result = await signInAction(formData);
        if (result.status === "error") {
          setRequestError(result.message);
          return;
        }
        router.replace(redirectTo);
        router.refresh();
      } catch {
        setRequestError("Sign in could not be completed. Please try again.");
      }
    });
  }

  return (
    <form className="space-y-5" noValidate onSubmit={form.handleSubmit(onSubmit)}>
      {requestError && (
        <Alert variant="destructive">
          <AlertTitle>Unable to sign in</AlertTitle>
          <AlertDescription>{requestError}</AlertDescription>
        </Alert>
      )}

      <div className="space-y-2">
        <Label htmlFor="login-email">Email address</Label>
        <div className="relative">
          <Mail aria-hidden="true" className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            {...form.register("email")}
            autoComplete="email"
            aria-describedby={form.formState.errors.email ? "login-email-error" : undefined}
            aria-invalid={Boolean(form.formState.errors.email)}
            className="h-11 pl-10"
            id="login-email"
            placeholder="you@company.com"
            type="email"
          />
        </div>
        {form.formState.errors.email && (
          <p className="text-xs text-destructive" id="login-email-error" role="alert">
            {form.formState.errors.email.message}
          </p>
        )}
      </div>

      <div className="space-y-2">
        <div className="flex items-center justify-between gap-3">
          <Label htmlFor="login-password">Password</Label>
          <span className="text-xs text-muted-foreground">Minimum 8 characters</span>
        </div>
        <Input
          {...form.register("password")}
          autoComplete="current-password"
          aria-describedby={form.formState.errors.password ? "login-password-error" : undefined}
          aria-invalid={Boolean(form.formState.errors.password)}
          className="h-11"
          id="login-password"
          placeholder="Enter your password"
          type="password"
        />
        {form.formState.errors.password && (
          <p className="text-xs text-destructive" id="login-password-error" role="alert">
            {form.formState.errors.password.message}
          </p>
        )}
      </div>

      <Button className="h-11 w-full text-sm font-semibold" disabled={isPending} type="submit">
        {isPending ? (
          <>
            <LoaderCircle aria-hidden="true" className="size-4 animate-spin" />
            Signing in…
          </>
        ) : (
          "Sign in to WebGuard"
        )}
      </Button>
      <p aria-live="polite" className="sr-only" role="status">
        {isPending ? "Signing in" : ""}
      </p>
    </form>
  );
}
