"use client";

import { useEffect } from "react";
import { CircleAlert } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function ProtectedRouteError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("Protected application route failed", error.digest);
  }, [error.digest]);

  return (
    <section className="flex min-h-[50vh] flex-col items-center justify-center px-5 text-center" role="alert">
      <CircleAlert aria-hidden="true" className="size-8 text-severity-high" />
      <h1 className="mt-4 text-lg font-semibold">This page could not be loaded</h1>
      <p className="mt-2 max-w-sm text-sm leading-6 text-muted-foreground">Your session remains protected. Try again, or return to the dashboard.</p>
      <Button className="mt-5" onClick={reset} variant="outline">Try again</Button>
    </section>
  );
}
